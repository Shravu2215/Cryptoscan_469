'use strict';

/** Editable identifier vocabulary for name-based sensitive-field detection. */
const SENSITIVE_NAME_SYNONYMS = {
  AADHAAR: ['aadhaar', 'aadhar', 'adhaar', 'uid', 'uidai'],
  PAN: ['pan', 'pan_number', 'permanent_account'],
  PAYMENT_CARD: [
    'card_number', 'cc_num', 'cvv', 'expiry', 'card_holder',
    'primary_account_number', 'credit_card_number', 'debit_card_number',
  ],
  HEALTH: ['diagnosis', 'icd', 'patient', 'prescription', 'medical_record', 'abha', 'blood_group'],
  PII_OTHER: ['phone', 'mobile', 'email', 'dob', 'date_of_birth', 'address'],
};

/** Column-type shapes that corroborate a name match; all values are heuristics. */
const COLUMN_TYPE_HINTS = {
  AADHAAR: { textLengths: [12], numericTypes: ['bigint', 'biginteger'] },
  PAN: { textLengths: [10], numericTypes: [] },
  PAYMENT_CARD: { textLengthRange: [13, 19], numericTypes: [] },
  HEALTH: { textLengths: [], numericTypes: [] },
  PII_OTHER: { textLengths: [], numericTypes: [] },
};

const PAYMENT_CONTEXT_CUES = [
  'payment', 'payments', 'card', 'credit', 'debit', 'cc', 'cc_num', 'cvv',
  'expiry', 'expiration', 'issuer', 'billing', 'merchant', 'card_holder',
  'primary_account_number',
];

const INCOME_TAX_CONTEXT_CUES = [
  'income_tax', 'taxpayer', 'tax_id', 'tax', 'permanent_account', 'pan_number',
];

const BOOLEAN_ENUM_TYPE_CUES = [
  'bool', 'boolean', 'enum', 'choice', 'yesno', 'flag',
];

const NAME_CONFIDENCE = 0.68;
const NAME_AND_TYPE_CONFIDENCE = 0.9;
const WEAK_BOOLEAN_ENUM_CONFIDENCE = 0.35;

module.exports = {
  SENSITIVE_NAME_SYNONYMS,
  COLUMN_TYPE_HINTS,
  PAYMENT_CONTEXT_CUES,
  INCOME_TAX_CONTEXT_CUES,
  BOOLEAN_ENUM_TYPE_CUES,
  NAME_CONFIDENCE,
  NAME_AND_TYPE_CONFIDENCE,
  WEAK_BOOLEAN_ENUM_CONFIDENCE,
};