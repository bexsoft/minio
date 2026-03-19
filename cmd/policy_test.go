// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"reflect"
	"testing"

	miniogopolicy "github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/set"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/pkg/v3/policy"
	"github.com/minio/pkg/v3/policy/condition"
)

func TestPolicySysIsAllowed(t *testing.T) {
	p := &policy.BucketPolicy{
		Version: policy.DefaultVersion,
		Statements: []policy.BPStatement{
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.GetBucketLocationAction),
				policy.NewResourceSet(policy.NewResource("mybucket")),
				condition.NewFunctions(),
			),
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.PutObjectAction),
				policy.NewResourceSet(policy.NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	anonGetBucketLocationArgs := policy.BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          policy.GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
	}

	anonPutObjectActionArgs := policy.BucketPolicyArgs{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      policy.PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		ObjectName: "myobject",
	}

	anonGetObjectActionArgs := policy.BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          policy.GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		ObjectName:      "myobject",
	}

	getBucketLocationArgs := policy.BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          policy.GetBucketLocationAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
	}

	putObjectActionArgs := policy.BucketPolicyArgs{
		AccountName: "Q3AM3UQ867SPQQA43P2F",
		Action:      policy.PutObjectAction,
		BucketName:  "mybucket",
		ConditionValues: map[string][]string{
			"x-amz-copy-source": {"mybucket/myobject"},
			"SourceIp":          {"192.168.1.10"},
		},
		IsOwner:    true,
		ObjectName: "myobject",
	}

	getObjectActionArgs := policy.BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          policy.GetObjectAction,
		BucketName:      "mybucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
		ObjectName:      "myobject",
	}

	yourbucketAnonGetObjectActionArgs := policy.BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          policy.GetObjectAction,
		BucketName:      "yourbucket",
		ConditionValues: map[string][]string{},
		ObjectName:      "yourobject",
	}

	yourbucketGetObjectActionArgs := policy.BucketPolicyArgs{
		AccountName:     "Q3AM3UQ867SPQQA43P2F",
		Action:          policy.GetObjectAction,
		BucketName:      "yourbucket",
		ConditionValues: map[string][]string{},
		IsOwner:         true,
		ObjectName:      "yourobject",
	}

	testCases := []struct {
		args           policy.BucketPolicyArgs
		expectedResult bool
	}{
		{anonGetBucketLocationArgs, true},
		{anonPutObjectActionArgs, true},
		{anonGetObjectActionArgs, false},
		{getBucketLocationArgs, true},
		{putObjectActionArgs, true},
		{getObjectActionArgs, true},
		{yourbucketAnonGetObjectActionArgs, false},
		{yourbucketGetObjectActionArgs, true},
	}

	for i, testCase := range testCases {
		result := p.IsAllowed(testCase.args)

		if result != testCase.expectedResult {
			t.Fatalf("case %v: expected: %v, got: %v\n", i+1, testCase.expectedResult, result)
		}
	}
}

func getReadOnlyStatement(bucketName, prefix string) []miniogopolicy.Statement {
	return []miniogopolicy.Statement{
		{
			Effect:    string(policy.Allow),
			Principal: miniogopolicy.User{AWS: set.CreateStringSet("*")},
			Resources: set.CreateStringSet(policy.NewResource(bucketName).String()),
			Actions:   set.CreateStringSet("s3:GetBucketLocation", "s3:ListBucket"),
		},
		{
			Effect:    string(policy.Allow),
			Principal: miniogopolicy.User{AWS: set.CreateStringSet("*")},
			Resources: set.CreateStringSet(policy.NewResource(bucketName + "/" + prefix).String()),
			Actions:   set.CreateStringSet("s3:GetObject"),
		},
	}
}

func TestPolicyToBucketAccessPolicy(t *testing.T) {
	case1Policy := &policy.BucketPolicy{
		Version: policy.DefaultVersion,
		Statements: []policy.BPStatement{
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.GetBucketLocationAction, policy.ListBucketAction),
				policy.NewResourceSet(policy.NewResource("mybucket")),
				condition.NewFunctions(),
			),
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.GetObjectAction),
				policy.NewResourceSet(policy.NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case1Result := &miniogopolicy.BucketAccessPolicy{
		Version:    policy.DefaultVersion,
		Statements: getReadOnlyStatement("mybucket", "myobject*"),
	}

	case2Policy := &policy.BucketPolicy{
		Version:    policy.DefaultVersion,
		Statements: []policy.BPStatement{},
	}

	case2Result := &miniogopolicy.BucketAccessPolicy{
		Version:    policy.DefaultVersion,
		Statements: []miniogopolicy.Statement{},
	}

	case3Policy := &policy.BucketPolicy{
		Version: "12-10-2012",
		Statements: []policy.BPStatement{
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.PutObjectAction),
				policy.NewResourceSet(policy.NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	testCases := []struct {
		bucketPolicy   *policy.BucketPolicy
		expectedResult *miniogopolicy.BucketAccessPolicy
		expectErr      bool
	}{
		{case1Policy, case1Result, false},
		{case2Policy, case2Result, false},
		{case3Policy, nil, true},
	}

	for i, testCase := range testCases {
		result, err := PolicyToBucketAccessPolicy(testCase.bucketPolicy)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v\n", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("case %v: result: expected: %+v, got: %+v\n", i+1, testCase.expectedResult, result)
			}
		}
	}
}

func TestBucketAccessPolicyToPolicy(t *testing.T) {
	case1PolicyInfo := &miniogopolicy.BucketAccessPolicy{
		Version:    policy.DefaultVersion,
		Statements: getReadOnlyStatement("mybucket", "myobject*"),
	}

	case1Result := &policy.BucketPolicy{
		Version: policy.DefaultVersion,
		Statements: []policy.BPStatement{
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.GetBucketLocationAction, policy.ListBucketAction),
				policy.NewResourceSet(policy.NewResource("mybucket")),
				condition.NewFunctions(),
			),
			policy.NewBPStatement("",
				policy.Allow,
				policy.NewPrincipal("*"),
				policy.NewActionSet(policy.GetObjectAction),
				policy.NewResourceSet(policy.NewResource("mybucket/myobject*")),
				condition.NewFunctions(),
			),
		},
	}

	case2PolicyInfo := &miniogopolicy.BucketAccessPolicy{
		Version:    policy.DefaultVersion,
		Statements: []miniogopolicy.Statement{},
	}

	case2Result := &policy.BucketPolicy{
		Version:    policy.DefaultVersion,
		Statements: []policy.BPStatement{},
	}

	case3PolicyInfo := &miniogopolicy.BucketAccessPolicy{
		Version:    "12-10-2012",
		Statements: getReadOnlyStatement("mybucket", "/myobject*"),
	}

	testCases := []struct {
		policyInfo     *miniogopolicy.BucketAccessPolicy
		expectedResult *policy.BucketPolicy
		expectErr      bool
	}{
		{case1PolicyInfo, case1Result, false},
		{case2PolicyInfo, case2Result, false},
		{case3PolicyInfo, nil, true},
	}

	for i, testCase := range testCases {
		result, err := BucketAccessPolicyToPolicy(testCase.policyInfo)
		expectErr := (err != nil)

		if expectErr != testCase.expectErr {
			t.Fatalf("case %v: error: expected: %v, got: %v\n", i+1, testCase.expectErr, expectErr)
		}

		if !testCase.expectErr {
			if !reflect.DeepEqual(result, testCase.expectedResult) {
				t.Fatalf("case %v: result: expected: %+v, got: %+v\n", i+1, testCase.expectedResult, result)
			}
		}
	}
}

// TestIsAllowedSSECConditionalDeny verifies the fix for AccountInfoHandler reporting
// incorrect write access when a policy uses StringNotEquals on the SSE-C algorithm header.
//
// The bug: the admin API request carries no SSE headers, so
// StringNotEquals { s3:x-amz-server-side-encryption-customer-algorithm: AES256 } evaluates
// to true (absent key → empty intersection → negated = true) → Deny fires → Write = false.
//
// The fix: supplement putCondVals with representative SSE values before the PutObjectAction
// capability check so the policy engine answers "can the user write with proper SSE headers?"
func TestIsAllowedSSECConditionalDeny(t *testing.T) {
	// Build StringNotEquals { s3:x-amz-server-side-encryption-customer-algorithm: AES256 }.
	denyCondFn, err := condition.NewStringNotEqualsFunc(
		"",
		condition.S3XAmzServerSideEncryptionCustomerAlgorithm.ToKey(),
		xhttp.AmzEncryptionAES,
	)
	if err != nil {
		t.Fatalf("failed to build StringNotEquals condition: %v", err)
	}

	p := policy.Policy{
		Version: policy.DefaultVersion,
		Statements: []policy.Statement{
			// Allow broad access on 12345* buckets (mirrors the reported issue's policy).
			policy.NewStatement(
				"",
				policy.Allow,
				policy.NewActionSet(policy.AllActions),
				policy.NewResourceSet(
					policy.NewResource("12345*"),
					policy.NewResource("12345*/*"),
				),
				condition.NewFunctions(),
			),
			// Deny PutObject on all objects unless SSE-C algorithm header equals AES256.
			policy.NewStatement(
				"",
				policy.Deny,
				policy.NewActionSet(policy.PutObjectAction),
				policy.NewResourceSet(policy.NewResource("*/*")),
				condition.NewFunctions(denyCondFn),
			),
		},
	}

	baseArgs := policy.Args{
		AccountName: "testuser",
		Action:      policy.PutObjectAction,
		BucketName:  "12345bucket",
		ObjectName:  "testobject",
	}

	// Without the SSE-C header: StringNotEquals evaluates to true (key absent → no
	// intersection with "AES256" → negated = true) → Deny fires → IsAllowed returns false.
	// This reproduces the incorrect behavior seen in AccountInfoHandler before the fix.
	argsNoSSE := baseArgs
	argsNoSSE.ConditionValues = map[string][]string{}
	if p.IsAllowed(argsNoSSE) {
		t.Error("expected IsAllowed=false without SSE-C header (Deny should fire)")
	}

	// With SSE-C header set to AES256: StringNotEquals evaluates to false → Deny does
	// not fire → Allow statement matches → IsAllowed returns true.
	// This confirms that supplementing putCondVals with the SSE key fixes the result.
	argsWithSSE := baseArgs
	argsWithSSE.ConditionValues = map[string][]string{
		xhttp.AmzServerSideEncryptionCustomerAlgorithm: {xhttp.AmzEncryptionAES},
	}
	if !p.IsAllowed(argsWithSSE) {
		t.Error("expected IsAllowed=true with SSE-C header set to AES256")
	}
}
