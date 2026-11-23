package server

import (
	"fmt"

	"github.com/46labs/auth0/pkg/config"
)

// deployConfiguredActions creates, deploys, and binds the config's Actions,
// in config order on each trigger. It runs in New, before anything is bound.
func (s *Server) deployConfiguredActions(deployed []config.DeployedAction) error {
	bound := map[string][]bindingRef{}
	for _, d := range deployed {
		trigger := d.Trigger
		if trigger == "" {
			trigger = TriggerPostLogin
		}
		version := ""
		for _, t := range supportedTriggers() {
			if t.ID == trigger {
				version = t.Version
			}
		}
		if version == "" {
			return fmt.Errorf("actions.deployed %q: %w %q", d.Name, errBadTrigger, trigger)
		}
		secrets := make([]ActionSecret, 0, len(d.Secrets))
		for _, sec := range d.Secrets {
			secrets = append(secrets, ActionSecret{Name: sec.Name, value: sec.Value})
		}
		a, err := s.actions.create(s.generateID(), Action{
			Name: d.Name, Code: d.Code, Runtime: d.Runtime, Secrets: secrets,
			SupportedTriggers: []ActionTriggerRef{{ID: trigger, Version: version}},
		})
		if err != nil {
			return fmt.Errorf("actions.deployed %q: %w", d.Name, err)
		}
		if _, err := s.actions.deploy(a.ID, s.generateID()); err != nil {
			return fmt.Errorf("actions.deployed %q: %w", d.Name, err)
		}
		bound[trigger] = append(bound[trigger], bindingRef{Type: "action_id", Value: a.ID})
	}
	for trigger, refs := range bound {
		if _, err := s.actions.setBindings(trigger, refs, s.generateID); err != nil {
			return fmt.Errorf("actions.deployed: bind %s: %w", trigger, err)
		}
	}
	return nil
}
