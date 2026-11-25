<!-- Generated file. Regenerate with: asago-guardrails-recommender catalog-index -->

# Rail Index

Generated from `guardrail-catalog/rails`. Regenerate with `asago-guardrails-recommender catalog-index`.

| Rail id | Mechanism | Tier | Needs LLM | Detects signals | Placement |
|---|---|---|---|---|---|
| `injection_detector_code` | injection_detection | 0 | no | code_payload | both |
| `injection_detector_sqli` | injection_detection | 0 | no | sql_payload | both |
| `injection_detector_template` | injection_detection | 0 | no | template_expr | both |
| `injection_detector_xss` | injection_detection | 0 | no | markup_script | both |
| `regex_action_confirmation` | regex_detection | 0 | no | unauthorized_action | output |
| `regex_fabricated_evidence` | regex_detection | 0 | no | fabricated_evidence | both |
| `regex_instruction_injection` | regex_detection | 0 | no | instruction_injection | both |
| `regex_social_engineering` | regex_detection | 0 | no | social_engineering | both |
| `pii_AGE` | sensitive_data_detection | 0 | no | pii:AGE | both |
| `pii_AU_ABN` | sensitive_data_detection | 0 | no | pii:AU_ABN | both |
| `pii_AU_ACN` | sensitive_data_detection | 0 | no | pii:AU_ACN | both |
| `pii_AU_MEDICARE` | sensitive_data_detection | 0 | no | pii:AU_MEDICARE | both |
| `pii_AU_TFN` | sensitive_data_detection | 0 | no | pii:AU_TFN | both |
| `pii_CA_PASSPORT` | sensitive_data_detection | 0 | no | pii:CA_PASSPORT | both |
| `pii_CREDIT_CARD` | sensitive_data_detection | 0 | no | pii:CREDIT_CARD | both |
| `pii_CRYPTO` | sensitive_data_detection | 0 | no | pii:CRYPTO | both |
| `pii_DATE_TIME` | sensitive_data_detection | 0 | no | pii:DATE_TIME | both |
| `pii_EMAIL` | sensitive_data_detection | 0 | no | pii:EMAIL | both |
| `pii_ES_NIE` | sensitive_data_detection | 0 | no | pii:ES_NIE | both |
| `pii_ES_NIF` | sensitive_data_detection | 0 | no | pii:ES_NIF | both |
| `pii_FI_PERSONAL_IDENTITY_CODE` | sensitive_data_detection | 0 | no | pii:FI_PERSONAL_IDENTITY_CODE | both |
| `pii_GENDER` | sensitive_data_detection | 0 | no | pii:GENDER | both |
| `pii_IBAN_CODE` | sensitive_data_detection | 0 | no | pii:IBAN_CODE | both |
| `pii_IN_AADHAAR` | sensitive_data_detection | 0 | no | pii:IN_AADHAAR | both |
| `pii_IN_GSTIN` | sensitive_data_detection | 0 | no | pii:IN_GSTIN | both |
| `pii_IN_PAN` | sensitive_data_detection | 0 | no | pii:IN_PAN | both |
| `pii_IN_PASSPORT` | sensitive_data_detection | 0 | no | pii:IN_PASSPORT | both |
| `pii_IN_VEHICLE_REGISTRATION` | sensitive_data_detection | 0 | no | pii:IN_VEHICLE_REGISTRATION | both |
| `pii_IN_VOTER` | sensitive_data_detection | 0 | no | pii:IN_VOTER | both |
| `pii_IP_ADDRESS` | sensitive_data_detection | 0 | no | pii:IP_ADDRESS | both |
| `pii_IT_DRIVER_LICENSE` | sensitive_data_detection | 0 | no | pii:IT_DRIVER_LICENSE | both |
| `pii_IT_FISCAL_CODE` | sensitive_data_detection | 0 | no | pii:IT_FISCAL_CODE | both |
| `pii_IT_IDENTITY_CARD` | sensitive_data_detection | 0 | no | pii:IT_IDENTITY_CARD | both |
| `pii_IT_PASSPORT` | sensitive_data_detection | 0 | no | pii:IT_PASSPORT | both |
| `pii_IT_VAT_CODE` | sensitive_data_detection | 0 | no | pii:IT_VAT_CODE | both |
| `pii_KR_BRN` | sensitive_data_detection | 0 | no | pii:KR_BRN | both |
| `pii_KR_DRIVER_LICENSE` | sensitive_data_detection | 0 | no | pii:KR_DRIVER_LICENSE | both |
| `pii_KR_FRN` | sensitive_data_detection | 0 | no | pii:KR_FRN | both |
| `pii_KR_PASSPORT` | sensitive_data_detection | 0 | no | pii:KR_PASSPORT | both |
| `pii_KR_RRN` | sensitive_data_detection | 0 | no | pii:KR_RRN | both |
| `pii_LOCATION` | sensitive_data_detection | 0 | no | pii:LOCATION | both |
| `pii_MAC_ADDRESS` | sensitive_data_detection | 0 | no | pii:MAC_ADDRESS | both |
| `pii_MEDICAL_LICENSE` | sensitive_data_detection | 0 | no | pii:MEDICAL_LICENSE | both |
| `pii_NG_NIN` | sensitive_data_detection | 0 | no | pii:NG_NIN | both |
| `pii_NG_VEHICLE_REGISTRATION` | sensitive_data_detection | 0 | no | pii:NG_VEHICLE_REGISTRATION | both |
| `pii_NRP` | sensitive_data_detection | 0 | no | pii:NRP | both |
| `pii_PERSON` | sensitive_data_detection | 0 | no | pii:PERSON | both |
| `pii_PHONE_NUMBER` | sensitive_data_detection | 0 | no | pii:PHONE_NUMBER | both |
| `pii_PL_PESEL` | sensitive_data_detection | 0 | no | pii:PL_PESEL | both |
| `pii_SG_NRIC_FIN` | sensitive_data_detection | 0 | no | pii:SG_NRIC_FIN | both |
| `pii_SG_UEN` | sensitive_data_detection | 0 | no | pii:SG_UEN | both |
| `pii_TH_TNIN` | sensitive_data_detection | 0 | no | pii:TH_TNIN | both |
| `pii_TITLE` | sensitive_data_detection | 0 | no | pii:TITLE | both |
| `pii_UK_NHS` | sensitive_data_detection | 0 | no | pii:UK_NHS | both |
| `pii_UK_NINO` | sensitive_data_detection | 0 | no | pii:UK_NINO | both |
| `pii_UK_PASSPORT` | sensitive_data_detection | 0 | no | pii:UK_PASSPORT | both |
| `pii_UK_POSTCODE` | sensitive_data_detection | 0 | no | pii:UK_POSTCODE | both |
| `pii_UK_VEHICLE_REGISTRATION` | sensitive_data_detection | 0 | no | pii:UK_VEHICLE_REGISTRATION | both |
| `pii_URL` | sensitive_data_detection | 0 | no | pii:URL | both |
| `pii_US_BANK_NUMBER` | sensitive_data_detection | 0 | no | pii:US_BANK_NUMBER | both |
| `pii_US_DRIVER_LICENSE` | sensitive_data_detection | 0 | no | pii:US_DRIVER_LICENSE | both |
| `pii_US_ITIN` | sensitive_data_detection | 0 | no | pii:US_ITIN | both |
| `pii_US_MBI` | sensitive_data_detection | 0 | no | pii:US_MBI | both |
| `pii_US_NPI` | sensitive_data_detection | 0 | no | pii:US_NPI | both |
| `pii_US_PASSPORT` | sensitive_data_detection | 0 | no | pii:US_PASSPORT | both |
| `pii_US_SSN` | sensitive_data_detection | 0 | no | pii:US_SSN | both |
| `hf_classifier_guardian-hap` | hf_classifier | 1 | no | harmful_language | both |
| `hf_classifier_prompt-injection` | hf_classifier | 1 | no | instruction_injection | both |
| `hf_classifier_wolf-defender` | hf_classifier | 1 | no | instruction_injection | both |
| `self_check_input_policy` | self_check_input | 2 | yes | social_engineering, fabricated_evidence, tool_misuse_request, exfiltration_request, instruction_injection | input |
| `self_check_output_policy` | self_check_output | 2 | yes | unauthorized_action, fabricated_evidence, social_engineering, exfiltration_request, harmful_language | output |
