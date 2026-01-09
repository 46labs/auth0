package client

import (
	"context"
	"fmt"
	"log"

	"github.com/auth0/go-auth0/management"
)

type Client struct {
	mgmt *management.Management
}

type Config struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Insecure     bool
}

func New(cfg Config) (*Client, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}

	opts := []management.Option{
		management.WithClientCredentials(context.Background(), cfg.ClientID, cfg.ClientSecret),
	}

	if cfg.Insecure {
		opts = append(opts, management.WithInsecure())
	}

	mgmt, err := management.New(cfg.Domain, opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing auth0 management client: %w", err)
	}

	return &Client{mgmt: mgmt}, nil
}

func (c *Client) CreateOrganization(ctx context.Context, name, displayName string, metadata map[string]string) (*management.Organization, error) {
	org := &management.Organization{
		Name:        &name,
		DisplayName: &displayName,
		Metadata:    &metadata,
	}

	if err := c.mgmt.Organization.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("creating organization: %w", err)
	}

	return org, nil
}

func (c *Client) GetOrganization(ctx context.Context, orgID string) (*management.Organization, error) {
	org, err := c.mgmt.Organization.Read(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("reading organization: %w", err)
	}

	return org, nil
}

func (c *Client) UpdateOrgMetadata(ctx context.Context, orgID string, metadata map[string]string) error {
	org := &management.Organization{
		Metadata: &metadata,
	}

	if err := c.mgmt.Organization.Update(ctx, orgID, org); err != nil {
		return fmt.Errorf("updating organization metadata: %w", err)
	}

	return nil
}

func (c *Client) ListOrganizations(ctx context.Context) ([]*management.Organization, error) {
	orgs, err := c.mgmt.Organization.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}

	return orgs.Organizations, nil
}

func (c *Client) AddUserToOrganization(ctx context.Context, orgID, userID, role string) error {
	log.Printf("Adding user %s to organization %s with role %s", userID, orgID, role)

	// Step 1: Add user to organization
	members := []string{userID}
	if err := c.mgmt.Organization.AddMembers(ctx, orgID, members); err != nil {
		return fmt.Errorf("adding user to organization: %w", err)
	}

	// Step 2: Assign role to the member
	if role != "" {
		roles := []string{role}
		if err := c.mgmt.Organization.AssignMemberRoles(ctx, orgID, userID, roles); err != nil {
			return fmt.Errorf("assigning role to member: %w", err)
		}
	}

	log.Printf("Successfully added user %s to organization %s with role %s", userID, orgID, role)
	return nil
}

func (c *Client) ListOrganizationMembers(ctx context.Context, orgID string) ([]management.OrganizationMember, error) {
	members, err := c.mgmt.Organization.Members(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing organization members: %w", err)
	}

	return members.Members, nil
}

func (c *Client) UpdateUserAppMetadata(ctx context.Context, userID string, appMetadata map[string]interface{}) error {
	user := &management.User{
		AppMetadata: &appMetadata,
	}

	if err := c.mgmt.User.Update(ctx, userID, user); err != nil {
		return fmt.Errorf("updating user app_metadata: %w", err)
	}

	return nil
}

func (c *Client) RemoveUserFromOrganization(ctx context.Context, orgID, userID string) error {
	members := []string{userID}
	if err := c.mgmt.Organization.DeleteMembers(ctx, orgID, members); err != nil {
		return fmt.Errorf("removing user from organization: %w", err)
	}

	log.Printf("Successfully removed user %s from organization %s", userID, orgID)
	return nil
}

func (c *Client) GetUser(ctx context.Context, userID string) (*management.User, error) {
	user, err := c.mgmt.User.Read(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("reading user: %w", err)
	}

	return user, nil
}
