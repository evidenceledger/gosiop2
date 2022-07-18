package authrequest

var claims_for_testing = []byte(`
{
	"id_token": {
	  "email": null
	},
	"vp_token": {
	  "presentation_definition": {
		"id": "customer_credentials",
		"format": {
		  "jwt_vc": {
			"alg": ["ES256", "ES384", "ES512"]
		  }
		},
		"input_descriptors": [
		  {
			"id": "CustomerCredential",
			"name": "Customer Credential",
			"purpose": "Check that user is a customer of a given type",
			"constraints": {
			  "fields": [
				{
				  "path": [
					"$.credentialSubject.customer_type"
				  ],
				  "filter": {
					"type": "string",
					"pattern": ["GoldCustomer", "NormalCustomer"]
				  }
				}
			  ]
			}
		  }
		]
	  }
	}
}
`)

var registration_json = []byte(`
{
  "subject_syntax_types_supported": ["did:peer",
  "did:elsi"]
}
`)

var vp_token_response = []byte(`
{
	"@context": ["https://www.w3.org/2018/credentials/v1"],
	"type": ["VerifiablePresentation"],
	"verifiableCredential": [
	  {
		"@context": [
		  "https://www.w3.org/2018/credentials/v1",
		  "https://i4trust.happypets.io/2022/credentials/customer/v1"
		],
		"id": "https://i4trust.happypets.io/credentials/1872",
		"type": ["VerifiableCredential", "CustomerCredential"],
		"issuer": {
		  "id": "did:elsi:EORNL-PACKETDELIVERY"
		},
		"issuanceDate": "2020-01-01T19:23:24Z",
		"credentialSubject": {
		  "id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
		  "verificationMethod": [
			{
			  "id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d#key1",
			  "type": "JwsVerificationKey2020",
			  "controller": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
			  "publicKeyJwk": {
				"kid": "key1",
				"kty": "EC",
				"crv": "secp256k1",
				"x": "lJtvoA5_XptBvcfcrvtGCvXd9bLymmfBSSdNJf5mogo",
				"y": "fSc4gZX2R3QKKfHvS3m2vGSVSN8Xc04qsquyfEM55Z0"
			  }
			}
		  ],
		  "customer_type": "GoldCustomer",
		  "name": "Jane Doe",
		  "given_name": "Jane",
		  "family_name": "Doe",
		  "preferred_username": "j.doe",
		  "email": "janedoe@packetdelivery.com"
		}
	  }
	]
}
`)
