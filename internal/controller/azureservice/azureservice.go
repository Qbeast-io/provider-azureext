package azureservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/pkg/errors"
	"github.com/qbeast-io/provider-azureext/apis/containerregistry/v1alpha1"
	"github.com/qbeast-io/provider-azureext/internal/controller/config"
)

type Service struct {
	registriesClient     *armcontainerregistry.RegistriesClient
	credentialSetsClient *armcontainerregistry.CredentialSetsClient
	cacheRulesClient     *armcontainerregistry.CacheRulesClient
}

func NewService(creds []byte) (interface{}, error) {
	credentials := &config.AzureCredentials{}
	err := json.Unmarshal(creds, credentials)
	if err != nil {
		return nil, err
	}
	cred, err := azidentity.NewClientSecretCredential(credentials.TenantId, credentials.ClientId, credentials.ClientSecret, &azidentity.ClientSecretCredentialOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}
	clientFactory, err := armcontainerregistry.NewClientFactory(credentials.SubscriptionId, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure registriesClient factory: %w", err)
	}
	registriesClient := clientFactory.NewRegistriesClient()
	credentialSetsClient := clientFactory.NewCredentialSetsClient()
	cacheRulesClient := clientFactory.NewCacheRulesClient()
	return &Service{registriesClient, credentialSetsClient, cacheRulesClient}, nil
}

func makeAuthCredentials(credentials []v1alpha1.AuthCredential) []*armcontainerregistry.AuthCredential {
	authCredentials := make([]*armcontainerregistry.AuthCredential, len(credentials))
	for i, cred := range credentials {
		credentialName := armcontainerregistry.CredentialName(cred.Name)
		authCredentials[i] = &armcontainerregistry.AuthCredential{
			Name:                     &credentialName,
			UsernameSecretIdentifier: &cred.UsernameSecretIdentifier,
			PasswordSecretIdentifier: &cred.PasswordSecretIdentifier,
		}
	}
	return authCredentials
}

var createdByTypes = map[string]armcontainerregistry.CreatedByType{
	"User":            armcontainerregistry.CreatedByTypeUser,
	"Application":     armcontainerregistry.CreatedByTypeApplication,
	"ManagedIdentity": armcontainerregistry.CreatedByTypeManagedIdentity,
	"Key":             armcontainerregistry.CreatedByTypeKey,
}

func makeCreatedByType(createdByType string) armcontainerregistry.CreatedByType {
	return createdByTypes[createdByType]
}

var lastModifiedByTypes = map[string]armcontainerregistry.LastModifiedByType{
	"User":            armcontainerregistry.LastModifiedByTypeUser,
	"Application":     armcontainerregistry.LastModifiedByTypeApplication,
	"ManagedIdentity": armcontainerregistry.LastModifiedByTypeManagedIdentity,
	"Key":             armcontainerregistry.LastModifiedByTypeKey,
}

func makeLastModifiedByType(lastModifiedByType string) armcontainerregistry.LastModifiedByType {
	return lastModifiedByTypes[lastModifiedByType]
}

func makeUserAssignedIdentities(identities map[string]v1alpha1.UserAssignedIdentity) map[string]*armcontainerregistry.UserIdentityProperties {
	userIdentities := make(map[string]*armcontainerregistry.UserIdentityProperties)
	for k, v := range identities {
		userIdentities[k] = &armcontainerregistry.UserIdentityProperties{
			ClientID:    &v.ClientId,
			PrincipalID: &v.PrincipalId,
		}
	}
	return userIdentities
}

func (s *Service) ObserveCredentialSet(ctx context.Context, spec *v1alpha1.CredentialSetSpec) (*v1alpha1.CredentialSetObservation, bool /* exists */, bool /* upToDate */, error) {
	res, err := s.credentialSetsClient.Get(ctx, spec.ForProvider.ResourceGroupName, spec.ForProvider.RegistryName, spec.ForProvider.Name, &armcontainerregistry.CredentialSetsClientGetOptions{})
	if err != nil {
		responseError := err.(*azcore.ResponseError)
		if responseError != nil && responseError.ErrorCode == "ResourceNotFound" {
			return &v1alpha1.CredentialSetObservation{}, false, false, nil // Not found
		}
		return nil, false, false, errors.New("failed to get credential set")
	}
	upToDate := credentialSetUpToDate(spec, res)
	return &v1alpha1.CredentialSetObservation{
		CreationDate:        res.SystemData.CreatedAt.String(),
		Id:                  *res.ID,
		Name:                *res.Name,
		ProvisioningState:   string(*res.Properties.ProvisioningState),
		Type:                *res.Type,
		IdentityType:        string(*res.Identity.Type),
		IdentityTenantId:    *res.Identity.TenantID,
		IdentityPrincipalId: *res.Identity.PrincipalID,
		Ready:               *res.Properties.ProvisioningState == armcontainerregistry.ProvisioningStateSucceeded,
		CreatedByType:       string(*res.SystemData.CreatedByType),
		CreatedAt:           res.SystemData.CreatedAt.String(),
		CreatedBy:           string(*res.SystemData.CreatedByType),
		LastModifiedByType:  string(*res.SystemData.LastModifiedByType),
		LastModifiedAt:      res.SystemData.LastModifiedAt.String(),
		LastModifiedBy:      *res.SystemData.LastModifiedBy,
	}, true, upToDate, err
}

func credentialSetUpToDate(spec *v1alpha1.CredentialSetSpec, res armcontainerregistry.CredentialSetsClientGetResponse) bool {
	if spec.ForProvider.LoginServer != *res.Properties.LoginServer ||
		(spec.ForProvider.Identity.PrincipalId != "" && spec.ForProvider.Identity.PrincipalId != *res.Identity.PrincipalID) {
		return false
	}

	if len(spec.ForProvider.AuthCredentials) != len(res.Properties.AuthCredentials) {
		return false
	}

	for i, authCred := range spec.ForProvider.AuthCredentials {
		if res.Properties.AuthCredentials[i].Name == nil || *res.Properties.AuthCredentials[i].Name != armcontainerregistry.CredentialName(authCred.Name) ||
			res.Properties.AuthCredentials[i].UsernameSecretIdentifier == nil || *res.Properties.AuthCredentials[i].UsernameSecretIdentifier != authCred.UsernameSecretIdentifier ||
			res.Properties.AuthCredentials[i].PasswordSecretIdentifier == nil || *res.Properties.AuthCredentials[i].PasswordSecretIdentifier != authCred.PasswordSecretIdentifier {
			return false
		}
	}

	return true
}

func (s *Service) ApplyCredentialSet(ctx context.Context, spec *v1alpha1.CredentialSetSpec) (*v1alpha1.CredentialSetObservation, error) {
	credentialSet := makeCredentialSet(spec)
	resp, err := s.credentialSetsClient.BeginCreate(
		ctx,
		spec.ForProvider.ResourceGroupName,
		spec.ForProvider.RegistryName,
		spec.ForProvider.Name,
		credentialSet,
		&armcontainerregistry.CredentialSetsClientBeginCreateOptions{},
	)
	if err != nil {
		return nil, errors.New("failed to create credential set")
	}
	res, err := resp.PollUntilDone(ctx, &runtime.PollUntilDoneOptions{})
	if err != nil {
		return nil, errors.New("failed to poll for credential set creation")
	}
	return &v1alpha1.CredentialSetObservation{
		CreationDate:        res.SystemData.CreatedAt.String(),
		Id:                  *res.ID,
		Name:                *res.Name,
		ProvisioningState:   string(*res.Properties.ProvisioningState),
		Type:                *res.Type,
		IdentityType:        string(*res.Identity.Type),
		IdentityTenantId:    *res.Identity.TenantID,
		IdentityPrincipalId: *res.Identity.PrincipalID,
		Ready:               *res.Properties.ProvisioningState == armcontainerregistry.ProvisioningStateSucceeded,
		CreatedByType:       string(*res.SystemData.CreatedByType),
		CreatedAt:           res.SystemData.CreatedAt.String(),
		CreatedBy:           string(*res.SystemData.CreatedByType),
		LastModifiedByType:  string(*res.SystemData.LastModifiedByType),
		LastModifiedAt:      res.SystemData.LastModifiedAt.String(),
		LastModifiedBy:      *res.SystemData.LastModifiedBy,
	}, nil
}

func makeCredentialSet(spec *v1alpha1.CredentialSetSpec) armcontainerregistry.CredentialSet {
	userAssignedIdentities := make(map[string]*armcontainerregistry.UserIdentityProperties)
	identityType := armcontainerregistry.ResourceIdentityType(spec.ForProvider.Identity.Type)
	credentialSet := armcontainerregistry.CredentialSet{
		Identity: &armcontainerregistry.IdentityProperties{
			Type:                   &identityType,
			PrincipalID:            &spec.ForProvider.Identity.PrincipalId,
			TenantID:               &spec.ForProvider.Identity.TenantId,
			UserAssignedIdentities: userAssignedIdentities,
		},
		Properties: &armcontainerregistry.CredentialSetProperties{
			AuthCredentials: makeAuthCredentials(spec.ForProvider.AuthCredentials),
			LoginServer:     &spec.ForProvider.LoginServer,
		},
	}
	return credentialSet
}

func (s *Service) DeleteCredentialSet(ctx context.Context, spec *v1alpha1.CredentialSetSpec) error {
	poller, err := s.credentialSetsClient.BeginDelete(ctx, spec.ForProvider.ResourceGroupName, spec.ForProvider.RegistryName, spec.ForProvider.Name, nil)
	if err != nil {
		return fmt.Errorf("failed to start deletion of credential set: %w", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to poll for credential set deletion: %w", err)
	}
	return nil
}

func (s *Service) ObserveCacheRule(ctx context.Context, spec *v1alpha1.CacheRuleSpec) (*v1alpha1.CacheRuleObservation, bool /* exists */, bool /* upToDate */, error) {
	res, err := s.cacheRulesClient.Get(ctx, spec.ForProvider.ResourceGroupName, spec.ForProvider.RegistryName, spec.ForProvider.CacheRuleName, &armcontainerregistry.CacheRulesClientGetOptions{})
	if err != nil {
		responseError := err.(*azcore.ResponseError)
		if responseError != nil && responseError.ErrorCode == "ResourceNotFound" {
			return &v1alpha1.CacheRuleObservation{}, false, false, nil // Not found
		}
		return nil, false, false, errors.New("failed to get credential set")
	}
	upToDate := cacheRuleUpToDate(spec, res)
	return &v1alpha1.CacheRuleObservation{
		CreationDate:       res.SystemData.CreatedAt.String(),
		Id:                 *res.ID,
		Name:               *res.Name,
		ProvisioningState:  string(*res.Properties.ProvisioningState),
		Type:               *res.Type,
		CreatedByType:      string(*res.SystemData.CreatedByType),
		CreatedAt:          res.SystemData.CreatedAt.String(),
		CreatedBy:          string(*res.SystemData.CreatedByType),
		LastModifiedByType: string(*res.SystemData.LastModifiedByType),
		LastModifiedAt:     res.SystemData.LastModifiedAt.String(),
		LastModifiedBy:     *res.SystemData.LastModifiedBy,
		Ready:              *res.Properties.ProvisioningState == armcontainerregistry.ProvisioningStateSucceeded,
	}, true, upToDate, err
}

func cacheRuleUpToDate(spec *v1alpha1.CacheRuleSpec, res armcontainerregistry.CacheRulesClientGetResponse) bool {
	if spec.ForProvider.SourceRepository != *res.Properties.SourceRepository ||
		spec.ForProvider.TargetRepository != *res.Properties.TargetRepository {
		return false
	}
	return true
}

func (s *Service) ApplyCacheRule(ctx context.Context, spec *v1alpha1.CacheRuleSpec) (*v1alpha1.CacheRuleObservation, error) {
	credentialSet, err := s.credentialSetsClient.Get(ctx, spec.ForProvider.ResourceGroupName, spec.ForProvider.RegistryName, spec.ForProvider.CredentialSetName, &armcontainerregistry.CredentialSetsClientGetOptions{})
	if err != nil {
		responseError := err.(*azcore.ResponseError)
		if responseError != nil && responseError.ErrorCode == "ResourceNotFound" {
			return nil, fmt.Errorf("credential set %s not found in registry %s in resource group %s", spec.ForProvider.CredentialSetName, spec.ForProvider.RegistryName, spec.ForProvider.ResourceGroupName)
		}
		return nil, errors.New("failed to get credential set")
	}
	resp, err := s.cacheRulesClient.BeginCreate(
		ctx,
		spec.ForProvider.ResourceGroupName,
		spec.ForProvider.RegistryName,
		spec.ForProvider.CacheRuleName,
		armcontainerregistry.CacheRule{
			Properties: &armcontainerregistry.CacheRuleProperties{
				CredentialSetResourceID: credentialSet.ID,
				SourceRepository:        &spec.ForProvider.SourceRepository,
				TargetRepository:        &spec.ForProvider.TargetRepository,
			},
		},
		&armcontainerregistry.CacheRulesClientBeginCreateOptions{},
	)
	if err != nil {
		return nil, errors.New("failed to create credential set")
	}
	res, err := resp.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, errors.New("failed to poll for credential set creation")
	}
	return &v1alpha1.CacheRuleObservation{
		CreationDate:       res.SystemData.CreatedAt.String(),
		Id:                 *res.ID,
		Name:               *res.Name,
		ProvisioningState:  string(*res.Properties.ProvisioningState),
		Type:               *res.Type,
		Ready:              *res.Properties.ProvisioningState == armcontainerregistry.ProvisioningStateSucceeded,
		CreatedByType:      string(*res.SystemData.CreatedByType),
		CreatedAt:          res.SystemData.CreatedAt.String(),
		CreatedBy:          string(*res.SystemData.CreatedByType),
		LastModifiedByType: string(*res.SystemData.LastModifiedByType),
		LastModifiedAt:     res.SystemData.LastModifiedAt.String(),
		LastModifiedBy:     *res.SystemData.LastModifiedBy,
	}, nil
}

func (s *Service) DeleteCacheRule(ctx context.Context, spec *v1alpha1.CacheRuleSpec) error {
	poller, err := s.cacheRulesClient.BeginDelete(ctx, spec.ForProvider.ResourceGroupName, spec.ForProvider.RegistryName, spec.ForProvider.CacheRuleName, nil)
	if err != nil {
		return fmt.Errorf("failed to start deletion of credential set: %w", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to poll for credential set deletion: %w", err)
	}
	return nil
}
