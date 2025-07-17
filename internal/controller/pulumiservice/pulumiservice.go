package pulumiservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optdestroy"
	"github.com/pulumi/pulumi/sdk/v3/go/common/apitype"
	"github.com/pulumi/pulumi/sdk/v3/go/common/workspace"
	"os"
	"strings"

	"github.com/pkg/errors"
	cr "github.com/pulumi/pulumi-azure-native-sdk/containerregistry/v3"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/pulumi/pulumi/sdk/v3/go/auto/optup"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/qbeast-io/provider-azureext/apis/containerregistry/v1alpha1"
	"github.com/qbeast-io/provider-azureext/internal/controller/config"
)

type Service struct {
	credentials *config.AzureCredentials
}

func NewService(creds []byte) (interface{}, error) {
	credentials := &config.AzureCredentials{}
	err := json.Unmarshal(creds, credentials)
	if err != nil {
		return nil, err
	}
	return &Service{credentials}, nil
}

func toConfigValues(credentials *config.AzureCredentials) map[string]auto.ConfigValue {
	return map[string]auto.ConfigValue{
		"azure-native:clientId":       {Value: credentials.ClientId},
		"azure-native:clientSecret":   {Value: credentials.ClientSecret},
		"azure-native:tenantId":       {Value: credentials.TenantId},
		"azure-native:subscriptionId": {Value: credentials.SubscriptionId},
	}
}

func toLookupCredentialSetArgs(credentialSet *v1alpha1.CredentialSetParameters) cr.LookupCredentialSetArgs {
	return cr.LookupCredentialSetArgs{
		CredentialSetName: credentialSet.Name,
		RegistryName:      credentialSet.RegistryName,
		ResourceGroupName: credentialSet.ResourceGroupName,
	}
}

func toLookupCacheRuleArgs(cacheRule *v1alpha1.CacheRuleParameters) cr.LookupCacheRuleArgs {
	return cr.LookupCacheRuleArgs{
		CacheRuleName:     cacheRule.CacheRuleName,
		RegistryName:      cacheRule.RegistryName,
		ResourceGroupName: cacheRule.ResourceGroupName,
	}
}

func toCredentialSetArgs(credentialSet v1alpha1.CredentialSetParameters) *cr.CredentialSetArgs {
	args := &cr.CredentialSetArgs{}
	credentialArray := make([]cr.AuthCredentialInput, len(credentialSet.AuthCredentials))
	for i, credential := range credentialSet.AuthCredentials {
		credentialArray[i] = cr.AuthCredentialArgs{
			Name:                     pulumi.String(credential.Name),
			PasswordSecretIdentifier: pulumi.String(credential.PasswordSecretIdentifier),
			UsernameSecretIdentifier: pulumi.String(credential.UsernameSecretIdentifier),
		}
	}
	var identityType cr.ResourceIdentityType
	if credentialSet.Identity.Type == "SystemAssigned" {
		args = &cr.CredentialSetArgs{
			AuthCredentials:   cr.AuthCredentialArray(credentialArray),
			CredentialSetName: pulumi.String(credentialSet.Name),
			Identity: cr.IdentityPropertiesArgs{
				Type: cr.ResourceIdentityTypeSystemAssigned,
			},
			LoginServer:       pulumi.String(credentialSet.LoginServer),
			RegistryName:      pulumi.String(credentialSet.RegistryName),
			ResourceGroupName: pulumi.String(credentialSet.ResourceGroupName),
		}
	} else {
		args = &cr.CredentialSetArgs{
			AuthCredentials:   cr.AuthCredentialArray(credentialArray),
			CredentialSetName: pulumi.String(credentialSet.Name),
			Identity: cr.IdentityPropertiesArgs{
				Type:                   identityType,
				UserAssignedIdentities: getUserIdentitiesFromSpec(credentialSet),
			},
			LoginServer:       pulumi.String(credentialSet.LoginServer),
			RegistryName:      pulumi.String(credentialSet.RegistryName),
			ResourceGroupName: pulumi.String(credentialSet.ResourceGroupName),
		}
	}
	return args
}

func removeStack(workspace auto.Workspace, ctx context.Context, s string) {
	err := workspace.RemoveStack(ctx, s)
	if err != nil {
		fmt.Printf("failed to remove stack: %v\n", err)
	}
}

var stackOptions = []auto.LocalWorkspaceOption{
	auto.EnvVars(map[string]string{"PULUMI_CONFIG_PASSPHRASE": "dummy"}),
	auto.Project(workspace.Project{
		Name:    "provider-azureext",
		Runtime: workspace.NewProjectRuntimeInfo("go", nil),
		Backend: &workspace.ProjectBackend{
			URL: "file:///tmp/pulumi",
		},
	}),
	auto.WorkDir("/tmp/pulumi"),
}

func exportCredentialSet(pctx *pulumi.Context, set *cr.CredentialSet) {
	pctx.Export("azureApiVersion", set.AzureApiVersion)
	pctx.Export("creationDate", set.CreationDate)
	pctx.Export("createdByType", set.SystemData.CreatedByType())
	pctx.Export("createdBy", set.SystemData.CreatedBy())
	pctx.Export("lastModifiedDate", set.SystemData.LastModifiedAt())
	pctx.Export("lastModifiedByType", set.SystemData.LastModifiedByType())
	pctx.Export("lastModifiedBy", set.SystemData.LastModifiedBy())
	pctx.Export("loginServer", set.LoginServer)
	pctx.Export("id", set.ID())
	pctx.Export("name", set.Name)
	pctx.Export("provisioningState", set.ProvisioningState)
	pctx.Export("type", set.Type)
	pctx.Export("identityPrincipalId", set.Identity.PrincipalId())
	pctx.Export("identityTenantId", set.Identity.TenantId())
	pctx.Export("identityType", set.Identity.Type())
}

func exportLookupCredentialSet(pctx *pulumi.Context, set *cr.LookupCredentialSetResult) {
	pctx.Export("azureApiVersion", pulumi.String(set.AzureApiVersion))
	pctx.Export("creationDate", pulumi.String(set.CreationDate))
	pctx.Export("createdByType", pulumi.String(*set.SystemData.CreatedByType))
	pctx.Export("createdBy", pulumi.String(*set.SystemData.CreatedBy))
	pctx.Export("lastModifiedDate", pulumi.String(*set.SystemData.LastModifiedAt))
	pctx.Export("lastModifiedByType", pulumi.String(*set.SystemData.LastModifiedByType))
	pctx.Export("lastModifiedBy", pulumi.String(*set.SystemData.LastModifiedBy))
	pctx.Export("loginServer", pulumi.String(*set.LoginServer))
	pctx.Export("id", pulumi.String(set.Id))
	pctx.Export("name", pulumi.String(set.Name))
	pctx.Export("provisioningState", pulumi.String(set.ProvisioningState))
	pctx.Export("type", pulumi.String(set.Type))
	pctx.Export("identityPrincipalId", pulumi.String(*set.Identity.PrincipalId))
	pctx.Export("identityTenantId", pulumi.String(*set.Identity.TenantId))
	pctx.Export("identityType", pulumi.String(*set.Identity.Type))
}

func exportLookupCacheRule(pctx *pulumi.Context, set *cr.LookupCacheRuleResult) {
	pctx.Export("azureApiVersion", pulumi.String(set.AzureApiVersion))
	pctx.Export("creationDate", pulumi.String(set.CreationDate))
	pctx.Export("createdByType", pulumi.String(*set.SystemData.CreatedByType))
	pctx.Export("createdBy", pulumi.String(*set.SystemData.CreatedBy))
	pctx.Export("lastModifiedDate", pulumi.String(*set.SystemData.LastModifiedAt))
	pctx.Export("lastModifiedByType", pulumi.String(*set.SystemData.LastModifiedByType))
	pctx.Export("lastModifiedBy", pulumi.String(*set.SystemData.LastModifiedBy))
	pctx.Export("id", pulumi.String(set.Id))
	pctx.Export("name", pulumi.String(set.Name))
	pctx.Export("provisioningState", pulumi.String(set.ProvisioningState))
	pctx.Export("type", pulumi.String(set.Type))
	pctx.Export("credentialSetResourceId", pulumi.String(*set.CredentialSetResourceId))
	pctx.Export("sourceRepository", pulumi.String(*set.SourceRepository))
	pctx.Export("targetRepository", pulumi.String(*set.TargetRepository))
}

func isNotFoundDestroyError(err error) bool {
	return strings.Contains(err.Error(), "not found")
}

func (s *Service) lookupCredentialSet(ctx context.Context, projectName string, spec *v1alpha1.CredentialSetSpec) (*auto.OutputMap, error) {
	lookupStack, err := s.getCredentialSetLookupStack(ctx, projectName, spec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get credential set lookup stack")
	}
	_, err = lookupStack.Up(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to credential set lookup stack")
	}
	outputs, err := lookupStack.Outputs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get credential set outputs")
	}
	return &outputs, nil
}

func (s *Service) getCredentialSetLookupStack(ctx context.Context, projectName string, spec *v1alpha1.CredentialSetSpec) (*auto.Stack, error) {
	lookupStackName := fmt.Sprintf("lookup-credentialset-%s", projectName)
	lookupProgram := func(pctx *pulumi.Context) error {
		args := toLookupCredentialSetArgs(&spec.ForProvider)
		credentialSet, err := cr.LookupCredentialSet(pctx, &args)
		if err != nil {
			return errors.Wrap(err, "error looking up credential set")
		}
		exportLookupCredentialSet(pctx, credentialSet)
		return nil
	}
	lookupStack, err := auto.UpsertStackInlineSource(ctx, lookupStackName, projectName, lookupProgram, stackOptions...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create applyStack")
	}
	err = lookupStack.SetAllConfig(ctx, toConfigValues(s.credentials))
	if err != nil {
		return nil, err
	}
	return &lookupStack, err
}

func (s *Service) getCredentialSetApplyStack(ctx context.Context, projectName string, spec *v1alpha1.CredentialSetSpec) (*auto.Stack, error) {
	stackName := projectName
	applyProgram := func(pctx *pulumi.Context) error {
		res, err := cr.NewCredentialSet(pctx, "credentialSet", toCredentialSetArgs(spec.ForProvider))
		exportCredentialSet(pctx, res)
		return errors.Wrap(err, "failed to create credential set")
	}
	applyStack, err := auto.UpsertStackInlineSource(ctx, stackName, projectName, applyProgram, stackOptions...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create applyStack")
	}
	err = applyStack.SetAllConfig(ctx, toConfigValues(s.credentials))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set config values")
	}
	return &applyStack, nil
}

func (s *Service) getCacheRuleApplyStack(ctx context.Context, projectName string, spec *v1alpha1.CacheRuleSpec) (*auto.Stack, error) {
	stackName := projectName
	applyProgram := func(pctx *pulumi.Context) error {
		res, err := cr.NewCacheRule(pctx, "credentialSet", toCacheRuleArgs(spec.ForProvider))
		exportCacheRule(pctx, res)
		return errors.Wrap(err, "failed to create cache rule")
	}
	applyStack, err := auto.UpsertStackInlineSource(ctx, stackName, projectName, applyProgram, stackOptions...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create applyStack")
	}
	err = applyStack.SetAllConfig(ctx, toConfigValues(s.credentials))
	if err != nil {
		return nil, errors.Wrap(err, "failed to set config values")
	}
	return &applyStack, nil
}

func (s *Service) lookupCacheRule(ctx context.Context, projectName string, spec *v1alpha1.CacheRuleSpec) (*auto.OutputMap, error) {
	lookupStack, err := s.getCacheRuleLookupStack(ctx, projectName, spec)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cache rule lookup stack")
	}
	_, err = lookupStack.Up(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to lookup cache rule")
	}
	outputs, err := lookupStack.Outputs(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get cache rule outputs")
	}
	return &outputs, nil
}

func (s *Service) getCacheRuleLookupStack(ctx context.Context, projectName string, spec *v1alpha1.CacheRuleSpec) (*auto.Stack, error) {
	lookupStackName := fmt.Sprintf("lookup-cacherule-%s", projectName)
	lookupProgram := func(pctx *pulumi.Context) error {
		args := toLookupCacheRuleArgs(&spec.ForProvider)
		cacheRule, err := cr.LookupCacheRule(pctx, &args)
		if err != nil {
			return errors.Wrap(err, "error looking up cache rule")
		}
		exportLookupCacheRule(pctx, cacheRule)
		return nil
	}
	lookupStack, err := auto.UpsertStackInlineSource(ctx, lookupStackName, projectName, lookupProgram, stackOptions...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create applyStack")
	}
	err = lookupStack.SetAllConfig(ctx, toConfigValues(s.credentials))
	if err != nil {
		return nil, err
	}
	return &lookupStack, err
}

func exportCacheRule(pctx *pulumi.Context, res *cr.CacheRule) {
	pctx.Export("azureApiVersion", res.AzureApiVersion)
	pctx.Export("creationDate", res.CreationDate)
	pctx.Export("createdByType", res.SystemData.CreatedByType())
	pctx.Export("createdBy", res.SystemData.CreatedBy())
	pctx.Export("lastModifiedDate", res.SystemData.LastModifiedAt())
	pctx.Export("lastModifiedByType", res.SystemData.LastModifiedByType())
	pctx.Export("lastModifiedBy", res.SystemData.LastModifiedBy())
	pctx.Export("id", res.ID())
	pctx.Export("name", res.Name)
	pctx.Export("provisioningState", res.ProvisioningState)
	pctx.Export("type", res.Type)
}

func toCacheRuleArgs(parameters v1alpha1.CacheRuleParameters) *cr.CacheRuleArgs {
	return &cr.CacheRuleArgs{
		CacheRuleName:           pulumi.String(parameters.CacheRuleName),
		CredentialSetResourceId: pulumi.String(parameters.CredentialSetResourceId),
		RegistryName:            pulumi.String(parameters.RegistryName),
		ResourceGroupName:       pulumi.String(parameters.ResourceGroupName),
		SourceRepository:        pulumi.String(parameters.SourceRepository),
		TargetRepository:        pulumi.String(parameters.TargetRepository),
	}
}

func (s *Service) ObserveCredentialSet(ctx context.Context, spec *v1alpha1.CredentialSetSpec) (*v1alpha1.CredentialSetObservation, bool /* exists */, bool /* upToDate */, error) {
	projectName := fmt.Sprintf("credset-%s", spec.ForProvider.Name)
	applyStack, err := s.getCredentialSetApplyStack(ctx, projectName, spec)
	if err != nil {
		return nil, false, false, errors.Wrap(err, "failed to get apply stack")
	}
	preview, err := applyStack.Preview(ctx)
	if err != nil {
		return nil, false, false, err
	}
	exists := preview.ChangeSummary[apitype.OpCreate] == 0
	upToDate := exists && preview.ChangeSummary[apitype.OpUpdate] == 0
	if !exists {
		return &v1alpha1.CredentialSetObservation{}, exists, upToDate, nil
	}
	outputs, err := s.lookupCredentialSet(ctx, projectName, spec)
	if err != nil {
		return nil, false, false, err
	}
	return &v1alpha1.CredentialSetObservation{
		AzureApiVersion:     (*outputs)["azureApiVersion"].Value.(string),
		CreationDate:        (*outputs)["creationDate"].Value.(string),
		Id:                  (*outputs)["id"].Value.(string),
		Name:                (*outputs)["name"].Value.(string),
		ProvisioningState:   (*outputs)["provisioningState"].Value.(string),
		Type:                (*outputs)["type"].Value.(string),
		IdentityType:        (*outputs)["identityType"].Value.(string),
		IdentityTenantId:    (*outputs)["identityTenantId"].Value.(string),
		IdentityPrincipalId: (*outputs)["identityPrincipalId"].Value.(string),
		Ready:               (*outputs)["provisioningState"].Value.(string) == "Succeeded",
		CreatedByType:       (*outputs)["createdByType"].Value.(string),
		CreatedAt:           (*outputs)["creationDate"].Value.(string),
		CreatedBy:           (*outputs)["createdBy"].Value.(string),
		LastModifiedByType:  (*outputs)["lastModifiedByType"].Value.(string),
		LastModifiedAt:      (*outputs)["lastModifiedDate"].Value.(string),
		LastModifiedBy:      (*outputs)["lastModifiedBy"].Value.(string),
	}, exists, upToDate, err
}

func (s *Service) ApplyCredentialSet(ctx context.Context, spec *v1alpha1.CredentialSetSpec) (*v1alpha1.CredentialSetObservation, error) {
	projectName := fmt.Sprintf("credset-%s", spec.ForProvider.Name)
	stack, err := s.getCredentialSetApplyStack(ctx, projectName, spec)
	if err != nil {
		return nil, err
	}
	res, err := stack.Up(ctx, optup.ProgressStreams(os.Stdout))
	if err != nil {
		return nil, err
	}
	return &v1alpha1.CredentialSetObservation{
		AzureApiVersion:     res.Outputs["azureApiVersion"].Value.(string),
		CreationDate:        res.Outputs["creationDate"].Value.(string),
		CreatedByType:       res.Outputs["createdByType"].Value.(string),
		CreatedBy:           res.Outputs["createdBy"].Value.(string),
		LastModifiedByType:  res.Outputs["lastModifiedByType"].Value.(string),
		LastModifiedAt:      res.Outputs["lastModifiedDate"].Value.(string),
		LastModifiedBy:      res.Outputs["lastModifiedBy"].Value.(string),
		Id:                  res.Outputs["id"].Value.(string),
		Name:                res.Outputs["name"].Value.(string),
		ProvisioningState:   res.Outputs["provisioningState"].Value.(string),
		Type:                res.Outputs["type"].Value.(string),
		IdentityPrincipalId: res.Outputs["identityPrincipalId"].Value.(string),
		IdentityTenantId:    res.Outputs["identityTenantId"].Value.(string),
		IdentityType:        res.Outputs["identityType"].Value.(string),
		Ready:               res.Outputs["provisioningState"].Value.(string) == "Succeeded",
	}, nil
}

func (s *Service) DeleteCredentialSet(ctx context.Context, spec *v1alpha1.CredentialSetSpec) error {
	projectName := fmt.Sprintf("credset-%s", spec.ForProvider.Name)
	stackName := projectName
	deleteProgram := func(_ *pulumi.Context) error {
		return nil
	}
	stack, err := auto.UpsertStackInlineSource(ctx, stackName, projectName, deleteProgram, stackOptions...)
	if err != nil {
		if auto.IsSelectStack404Error(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to select Pulumi stack: %w", err)
	}
	_, err = stack.Destroy(ctx, optdestroy.ProgressStreams(os.Stdout))
	if err != nil && isNotFoundDestroyError(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to destroy stack: %w", err)
	}
	removeStack(stack.Workspace(), ctx, stackName)
	return nil
}

func (s *Service) ObserveCacheRule(ctx context.Context, spec *v1alpha1.CacheRuleSpec) (*v1alpha1.CacheRuleObservation, bool /* exists */, bool /* upToDate */, error) {
	projectName := fmt.Sprintf("cacherule-%s", spec.ForProvider.CacheRuleName)
	applyStack, err := s.getCacheRuleApplyStack(ctx, projectName, spec)
	preview, err := applyStack.Preview(ctx)
	if err != nil {
		return nil, false, false, err
	}
	exists := preview.ChangeSummary[apitype.OpCreate] == 0
	upToDate := exists && preview.ChangeSummary[apitype.OpUpdate] == 0
	if !exists {
		return &v1alpha1.CacheRuleObservation{}, exists, upToDate, nil
	}
	outputs, err := s.lookupCacheRule(ctx, projectName, spec)
	if err != nil {
		return nil, false, false, err
	}
	return &v1alpha1.CacheRuleObservation{
		AzureApiVersion:    (*outputs)["azureApiVersion"].Value.(string),
		CreationDate:       (*outputs)["azureApiVersion"].Value.(string),
		Id:                 (*outputs)["creationDate"].Value.(string),
		Name:               (*outputs)["id"].Value.(string),
		ProvisioningState:  (*outputs)["name"].Value.(string),
		Type:               (*outputs)["type"].Value.(string),
		CreatedByType:      (*outputs)["createdByType"].Value.(string),
		CreatedAt:          (*outputs)["creationDate"].Value.(string),
		CreatedBy:          (*outputs)["createdBy"].Value.(string),
		LastModifiedByType: (*outputs)["lastModifiedByType"].Value.(string),
		LastModifiedAt:     (*outputs)["lastModifiedDate"].Value.(string),
		LastModifiedBy:     (*outputs)["lastModifiedBy"].Value.(string),
		Ready:              (*outputs)["provisioningState"].Value.(string) == "Succeeded",
	}, exists, upToDate, nil
}

func (s *Service) ApplyCacheRule(ctx context.Context, spec *v1alpha1.CacheRuleSpec) (*v1alpha1.CacheRuleObservation, error) {
	projectName := fmt.Sprintf("cacherule-%s", spec.ForProvider.CacheRuleName)
	if spec.ForProvider.CredentialSetResourceId == "" {
		credentialSet, err := s.lookupCredentialSet(ctx, projectName, &v1alpha1.CredentialSetSpec{
			ForProvider: v1alpha1.CredentialSetParameters{
				Name:              spec.ForProvider.CredentialSetName,
				RegistryName:      spec.ForProvider.RegistryName,
				ResourceGroupName: spec.ForProvider.ResourceGroupName,
			},
		})
		if err != nil {
			return nil, err
		}
		spec.ForProvider.CredentialSetResourceId = (*credentialSet)["id"].Value.(string)
	}
	stack, err := s.getCacheRuleApplyStack(ctx, projectName, spec)
	if err != nil {
		return nil, err
	}
	res, err := stack.Up(ctx, optup.ProgressStreams(os.Stdout))
	if err != nil {
		return nil, err
	}
	return &v1alpha1.CacheRuleObservation{
		AzureApiVersion:    res.Outputs["azureApiVersion"].Value.(string),
		CreationDate:       res.Outputs["creationDate"].Value.(string),
		Id:                 res.Outputs["id"].Value.(string),
		Name:               res.Outputs["name"].Value.(string),
		ProvisioningState:  res.Outputs["provisioningState"].Value.(string),
		Type:               res.Outputs["type"].Value.(string),
		CreatedByType:      res.Outputs["createdByType"].Value.(string),
		CreatedAt:          res.Outputs["creationDate"].Value.(string),
		CreatedBy:          res.Outputs["createdBy"].Value.(string),
		LastModifiedByType: res.Outputs["lastModifiedByType"].Value.(string),
		LastModifiedAt:     res.Outputs["lastModifiedDate"].Value.(string),
		LastModifiedBy:     res.Outputs["lastModifiedBy"].Value.(string),
		Ready:              res.Outputs["provisioningState"].Value.(string) == "Succeeded",
	}, nil
}

func (s *Service) DeleteCacheRule(ctx context.Context, spec *v1alpha1.CacheRuleSpec) error {
	projectName := fmt.Sprintf("credset-%s", spec.ForProvider.CacheRuleName)
	stackName := projectName

	stack, err := auto.SelectStackInlineSource(ctx, stackName, spec.ForProvider.ResourceGroupName, func(ctx *pulumi.Context) error {
		return nil
	})
	if err != nil {
		if auto.IsSelectStack404Error(err) {
			return nil // Already deleted
		}
		return fmt.Errorf("failed to select Pulumi stack: %w", err)
	}

	_, err = stack.Destroy(ctx)
	if err != nil {
		return fmt.Errorf("failed to destroy stack: %w", err)
	}

	err = stack.Workspace().RemoveStack(ctx, stackName)
	if err != nil {
		return fmt.Errorf("failed to remove stack: %w", err)
	}

	return nil
}

func getUserIdentitiesFromSpec(spec v1alpha1.CredentialSetParameters) cr.UserIdentityPropertiesMap {
	identities := make(cr.UserIdentityPropertiesMap)
	for k, v := range spec.Identity.UserAssignedIdentities {
		identities[k] = cr.UserIdentityPropertiesArgs{
			ClientId:    pulumi.String(v.ClientId),
			PrincipalId: pulumi.String(v.PrincipalId),
		}
	}
	return identities
}
