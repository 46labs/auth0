package server

import (
	"errors"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/46labs/auth0/pkg/config"
)

// Acceptance failures. Auth0 tells the caller only "not valid"; the mock
// separates them so a failing local test says which rule tripped.
var (
	// unknown, already-redeemed, revoked or expired — indistinguishable by design
	errInvitationNotFound     = errors.New("the invitation is not valid")
	errInvitationWrongInvitee = errors.New("the invitation was issued to a different address")
	errInvitationWrongClient  = errors.New("the invitation was issued for a different application")
	errInvitationRoleGone     = errors.New("the invitation's role no longer exists")
)

// invitationTicket identifies an invitation in a login request.
type invitationTicket struct {
	OrgID    string
	TicketID string
	ClientID string
}

// ticketFromQuery returns false for an ordinary login carrying no invitation.
func ticketFromQuery(q url.Values) (invitationTicket, bool) {
	ticketID := q.Get("invitation")
	if ticketID == "" {
		return invitationTicket{}, false
	}
	return invitationTicket{
		OrgID:    q.Get("organization"),
		TicketID: ticketID,
		ClientID: q.Get("client_id"),
	}, true
}

// lookupInvitation resolves a ticket without consuming it. Caller holds the
// write lock, since expired invitations are pruned.
func (s *Server) lookupInvitation(t invitationTicket, now time.Time) (*config.OrganizationInvitation, error) {
	if t.OrgID == "" {
		return nil, errInvitationNotFound
	}
	if _, ok := s.organizations[t.OrgID]; !ok {
		return nil, errInvitationNotFound
	}
	pending := s.pendingInvitations(t.OrgID, now)
	for i := range pending {
		if pending[i].TicketID != t.TicketID {
			continue
		}
		// Redeeming through a different client would issue a token for an
		// application never invited. No client_id is a mismatch, not an
		// exemption — every invitation is created bound to one.
		if pending[i].ClientID != "" && t.ClientID != pending[i].ClientID {
			return nil, errInvitationWrongClient
		}
		return &pending[i], nil
	}
	return nil, errInvitationNotFound
}

// authorizeOrgLoginLocked authorizes an org-scoped login that is not an
// invitation redemption. Without it any caller could name an arbitrary
// organization and get a token carrying its org_id. Caller holds the lock.
func (s *Server) authorizeOrgLoginLocked(user *config.User, orgID string) error {
	if orgID == "" {
		return nil
	}
	if _, ok := s.organizations[orgID]; !ok {
		return errOrgNotFound
	}

	for _, m := range s.members[orgID] {
		if m.UserID == user.ID {
			return nil
		}
	}

	// Auth0's escape hatch: the directory self-serves into the org by
	// authenticating against a connection that grants membership on login.
	for _, oc := range s.orgConnections[orgID] {
		if !oc.AssignMembershipOnLogin {
			continue
		}
		stored, ok := s.users[user.ID]
		if !ok {
			return errOrgNotMember
		}
		s.addMemberLocked(orgID, stored, "")
		return nil
	}

	return errOrgNotMember
}

// Org-scoped login failures.
var (
	errOrgNotFound  = errors.New("the organization does not exist")
	errOrgNotMember = errors.New("the user is not a member of the organization")
)

// authorizeOrgLogin is authorizeOrgLoginLocked with the lock taken.
func (s *Server) authorizeOrgLogin(user *config.User, orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorizeOrgLoginLocked(user, orgID)
}

// roleForOrg resolves the role claim for the scoped organization. org_roles is
// authoritative; the flat role only applies to its own tenant_id, else an
// admin of one org would carry that role into every other one.
func roleForOrg(user *config.User, orgID string) string {
	if role := user.AppMetadata.OrgRole(orgID); role != "" {
		return role
	}
	if orgID == "" || user.AppMetadata.TenantID() == orgID {
		return user.AppMetadata.Role()
	}
	return ""
}

// redeemInvitation consumes a pending invitation, creating the user when the
// email is unknown. One-time: the removal shares the lock with the read, so a
// replay or a concurrent second attempt finds nothing.
func (s *Server) redeemInvitation(t invitationTicket, identifier string, now time.Time) (*config.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inv, err := s.lookupInvitation(t, now)
	if err != nil {
		return nil, err
	}

	// The ticket is bound to the invited address, compared case insensitively.
	if !strings.EqualFold(strings.TrimSpace(identifier), inv.InviteeEmail) {
		return nil, errInvitationWrongInvitee
	}

	user := s.findUserLocked(inv.InviteeEmail)
	if user == nil {
		user = s.autoCreateUserLocked(inv.InviteeEmail)
	}

	stored, ok := s.users[user.ID]
	if !ok {
		return nil, errInvitationNotFound
	}

	// Invitations carry role ids; org_roles holds the name. A role deleted
	// between create and acceptance must fail the redemption, not quietly
	// grant nothing.
	role := ""
	if len(inv.Roles) > 0 {
		role = s.roleNameByID(inv.Roles[0])
		if role == "" {
			return nil, errInvitationRoleGone
		}
	}

	s.addMemberLocked(t.OrgID, stored, role)
	s.applyInvitationMetadataLocked(stored, inv, t.OrgID, role)

	s.removeInvitationLocked(t.OrgID, inv.ID)

	log.Printf("Invitation %s redeemed by %s into %s (role %q)", inv.ID, inv.InviteeEmail, t.OrgID, role)
	return stored.Clone(), nil
}

// addMemberLocked requires the caller to hold the write lock.
func (s *Server) addMemberLocked(orgID string, user *config.User, role string) {
	members := s.members[orgID]
	for i := range members {
		if members[i].UserID == user.ID {
			if role != "" {
				members[i].Role = role
			}
			return
		}
	}
	s.members[orgID] = append(members, config.OrganizationMember{
		UserID: user.ID,
		OrgID:  orgID,
		Role:   role,
	})

	for _, existing := range user.Organizations {
		if existing == orgID {
			return
		}
	}
	user.Organizations = append(user.Organizations, orgID)
}

// applyInvitationMetadataLocked requires the caller to hold the write lock.
func (s *Server) applyInvitationMetadataLocked(
	user *config.User, inv *config.OrganizationInvitation, orgID, role string,
) {
	if user.AppMetadata == nil {
		user.AppMetadata = config.AppMetadata{}
	}
	// Auth0 copies invitation metadata onto the profile on acceptance, which
	// is what would let an invitation carry org_roles directly and retire both
	// the carrier role and the seeding below. Undocumented; see Known gaps.
	for k, v := range inv.AppMetadata.Clone() {
		user.AppMetadata[k] = v
	}
	if len(inv.UserMetadata) > 0 {
		if user.UserMetadata == nil {
			user.UserMetadata = map[string]any{}
		}
		for k, v := range config.AppMetadata(inv.UserMetadata).Clone() {
			user.UserMetadata[k] = v
		}
	}

	// tenant_id now names the org just joined, so the flat role must describe
	// it too. No role on the invitation means none here — leaving the previous
	// tenant's value would grant this org a role inherited from another.
	user.AppMetadata[config.AppMetaTenantID] = orgID
	if role != "" {
		user.AppMetadata[config.AppMetaRole] = role
	} else {
		delete(user.AppMetadata, config.AppMetaRole)
	}
	s.seedOrgRoleLocked(user, orgID, role)
}

// removeInvitationLocked requires the caller to hold the write lock.
func (s *Server) removeInvitationLocked(orgID, invitationID string) {
	stored := s.invitations[orgID]
	for i := range stored {
		if stored[i].ID == invitationID {
			s.invitations[orgID] = append(stored[:i:i], stored[i+1:]...)
			return
		}
	}
}

// seedOrgRoleLocked writes app_metadata.org_roles[orgID] when absent, which is
// the Post-Login Action's job. Only on absence: after the first login
// org_roles is authoritative and a later role write owns it. Caller holds the
// write lock.
func (s *Server) seedOrgRoleLocked(user *config.User, orgID, role string) bool {
	if orgID == "" || role == "" {
		return false
	}
	if user.AppMetadata == nil {
		user.AppMetadata = config.AppMetadata{}
	}
	if user.AppMetadata.OrgRole(orgID) != "" {
		return false
	}

	orgRoles, ok := user.AppMetadata[config.AppMetaOrgRoles].(map[string]any)
	if !ok {
		orgRoles = map[string]any{}
		user.AppMetadata[config.AppMetaOrgRoles] = orgRoles
	}
	orgRoles[orgID] = role
	return true
}

// seedOrgRoles derives the org-scoped role from membership and persists it
// under app_metadata.org_roles when absent, so a Management API reader sees the
// model production writes.
func (s *Server) seedOrgRoles(userID, orgID string) *config.User {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, ok := s.users[userID]
	if !ok {
		return nil
	}
	if orgID == "" {
		return user.Clone()
	}

	role := ""
	for _, m := range s.members[orgID] {
		if m.UserID == userID {
			role = m.Role
			break
		}
	}
	if s.seedOrgRoleLocked(user, orgID, role) {
		log.Printf("Seeded app_metadata.org_roles[%s]=%q for %s", orgID, role, userID)
	}
	return user.Clone()
}
