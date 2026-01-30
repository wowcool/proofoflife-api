import { sql } from "drizzle-orm";
import { pgTable, text, varchar, integer, bigint, timestamp, jsonb, boolean, serial, date, uuid } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";

// User accounts table (master identity only)
export const userAccounts = pgTable("user_accounts", {
  id: serial("id").primaryKey(),
  clerkUserId: varchar("clerk_user_id", { length: 255 }).unique(), // Clerk integration (SSO) - nullable for World Wallet users
  walletAddress: varchar("wallet_address", { length: 42 }).unique(), // World Wallet address (for World mini app users)
  authType: varchar("auth_type", { length: 20 }).default("clerk").notNull(), // 'clerk' or 'world_wallet'
  masterAddress: varchar("master_address", { length: 42 }).notNull(), // Ethereum address
  encryptedPrivateKey: text("encrypted_private_key"), // Encrypted with MEK (V5.1)
  wrappedMek: text("wrapped_mek"), // MEK wrapped with server KEK (V5.1)
  passkeyEnrolled: boolean("passkey_enrolled").default(false), // V5.1 passkey enrollment status
  createdAt: timestamp("created_at").default(sql`NOW()`),
  lastActive: timestamp("last_active").default(sql`NOW()`),
  accountStatus: varchar("account_status", { length: 20 }).default("active"), // active, suspended, deleted
  metadata: jsonb("metadata").default(sql`'{}'::jsonb`),
  
  // Single-Device Enforcement (V5.0)
  activeDeviceId: varchar("active_device_id", { length: 36 }), // UUID of currently logged-in device
  activeSessionId: varchar("active_session_id", { length: 255 }), // Clerk session ID for the active device
  lastLoginAt: timestamp("last_login_at"), // Timestamp of most recent login
  
  // Sleep Mode - Privacy-preserving heartbeat tracking (NO location storage!)
  lastHeartbeat: timestamp("last_heartbeat"), // When user last uploaded to IPFS
  lastSilentPush: timestamp("last_silent_push"), // When we last sent a push notification
  sleepModeEnabled: boolean("sleep_mode_enabled").default(false), // User preference
  expoPushToken: text("expo_push_token"), // Expo push notification token
  batteryLevel: varchar("battery_level", { length: 5 }), // "0.75" as string (telemetry)
  isCharging: boolean("is_charging"), // Charging status (telemetry)
  
  // Daytime Inactivity Ping (V5.2) - 30-minute check for stationary users
  lastInactivityPing: timestamp("last_inactivity_ping"), // When we last sent a daytime inactivity push
  autoRecordEnabled: boolean("auto_record_enabled").default(false), // Whether auto-record is on (from mobile heartbeat)
  
  // App Reminder Notification - 1-hour heartbeat stale reminder
  lastAppReminderPush: timestamp("last_app_reminder_push"), // When we last sent app reminder notification
  recordingIntensity: varchar("recording_intensity", { length: 20 }).default("balanced"), // 'minimal', 'conservative', 'balanced', 'aggressive'
  
  // Auto-Anchoring - Automatic location anchoring preference
  autoAnchoringEnabled: boolean("auto_anchoring_enabled").default(true), // User preference (default: enabled)
  
  // Subscription Tier - tracks if user is paid or free
  subscriptionTier: varchar("subscription_tier", { length: 20 }).default("free"), // 'free' or 'paid'
});

// Devices table (V5.1 - Passkey-enabled devices)
// V7.5: Added deviceFingerprint for dual-factor device identification (credentialId + fingerprint)
// This fixes the iCloud Keychain passkey sync bug where multiple physical devices share the same credentialId
export const devices = pgTable("devices", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: integer("user_id").notNull().references(() => userAccounts.id, { onDelete: 'cascade' }),
  deviceName: text("device_name"),
  deviceModel: text("device_model"),
  osVersion: text("os_version"),
  deviceFingerprint: text("device_fingerprint"), // V7.5: Unique device identifier (persistent UUID from Keychain, NOT synced to iCloud)
  expoPushToken: text("expo_push_token"), // V7.6: Per-device push token for reliable logout notifications
  passkeyCredentialId: text("passkey_credential_id").unique(),
  passkeyPublicKey: text("passkey_public_key"),
  passkeyCounter: integer("passkey_counter").default(0),
  isActive: boolean("is_active").default(true),
  lastSeenAt: timestamp("last_seen_at").default(sql`NOW()`),
  createdAt: timestamp("created_at").default(sql`NOW()`),
  revokedAt: timestamp("revoked_at"),
});

// Passkey challenges table (V5.1 - WebAuthn challenge storage)
export const passkeyChallenges = pgTable("passkey_challenges", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: integer("user_id").notNull().references(() => userAccounts.id, { onDelete: 'cascade' }),
  challenge: text("challenge").notNull(),
  type: varchar("type", { length: 20 }).notNull(), // 'registration' or 'authentication'
  expiresAt: timestamp("expires_at").notNull(),
  used: boolean("used").default(false),
  createdAt: timestamp("created_at").default(sql`NOW()`),
});

// NOTE: Anchors table removed for privacy - all anchor data is on-chain and indexed by The Graph
// V3.5.1: userAnchorsIndex table removed - eliminated privacy leak
// Server NEVER stores anchor addresses to preserve unlinkability between user accounts and anchors
// All anchor lookups done via The Graph using client-provided recoveryHints (TRUE PRIVACY)

// User nonces index (V3.5.1 - bootstrap recovery without privacy leak)
// Stores nonces for anchor recovery after cache clearing
// Privacy: sessionHash is irreversible, nonces are already public on blockchain
export const userNoncesIndex = pgTable("user_nonces_index", {
  id: serial("id").primaryKey(),
  sessionHash: varchar("session_hash", { length: 64 }).notNull(), // SHA256(masterAddress + SERVER_SALT)
  anchorNonce: varchar("anchor_nonce", { length: 66 }).notNull(), // uint256 hex string (0x...)
  createdAt: timestamp("created_at").default(sql`NOW()`),
});

// Burned anchors table (V3.1 - tracks permanently burned anchors)
export const burnedAnchors = pgTable("burned_anchors", {
  id: serial("id").primaryKey(),
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull().unique(), // Burned anchor address
  proofTxHash: varchar("proof_tx_hash", { length: 66 }), // Ownership proof transaction that burned it
  blockNumber: bigint("block_number", { mode: "number" }), // Block number of burn
  masterAddress: varchar("master_address", { length: 42 }), // Master wallet that created the proof (optional)
  burnedAt: timestamp("burned_at").default(sql`NOW()`), // When the anchor was burned
});

// Device attestations table (for verified iOS/Android devices)
export const deviceAttestations = pgTable("device_attestations", {
  id: serial("id").primaryKey(),
  deviceId: varchar("device_id", { length: 64 }).notNull().unique(), // Cryptographic hash
  masterAddress: varchar("master_address", { length: 42 }).notNull(),
  platform: varchar("platform", { length: 10 }).notNull(), // 'ios' or 'android'
  trustLevel: varchar("trust_level", { length: 20 }).notNull(), // 'basic', 'device', 'strong'
  attestationData: text("attestation_data").notNull(), // Stored attestation for validation
  verifiedAt: timestamp("verified_at").default(sql`NOW()`),
  expiresAt: timestamp("expires_at").notNull(),
  lastUsedAt: timestamp("last_used_at"),
});

// Ownership proofs table (ONLY when user explicitly reveals)
export const ownershipProofs = pgTable("ownership_proofs", {
  id: serial("id").primaryKey(),
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull(), // Anchor address being proven
  masterAddress: varchar("master_address", { length: 42 }).notNull(),
  anchorTimestamp: bigint("anchor_timestamp", { mode: "number" }).notNull(), // Unix timestamp (ms) when anchor was created
  proofSignature: text("proof_signature").notNull(), // Cryptographic proof
  proofTimestamp: timestamp("proof_timestamp").default(sql`NOW()`),
  expiresAt: timestamp("expires_at"), // Optional expiration
});

// Proof requests table (temporary proof generation)
export const proofRequests = pgTable("proof_requests", {
  id: serial("id").primaryKey(),
  requestId: uuid("request_id").notNull().unique(),
  masterAddress: varchar("master_address", { length: 42 }).notNull(), // User requesting proof
  dateRangeStart: date("date_range_start").notNull(),
  dateRangeEnd: date("date_range_end").notNull(),
  proofType: varchar("proof_type", { length: 20 }).notNull(), // location, presence, path
  status: varchar("status", { length: 20 }).default("pending"), // pending, ready, expired
  proofData: jsonb("proof_data"),
  createdAt: timestamp("created_at").default(sql`NOW()`),
  expiresAt: timestamp("expires_at").notNull(),
});

// Public proofs table (shareable proof pages)
export const publicProofs = pgTable("public_proofs", {
  id: serial("id").primaryKey(),
  proofId: uuid("proof_id").notNull().unique(), // UUID for public URL
  masterAddress: varchar("master_address", { length: 42 }).notNull(),
  anchorAddresses: text("anchor_addresses").array().notNull(), // Array of revealed anchor addresses
  anchorPrivateKey: text("anchor_private_key"), // Anchor private key (safe to share after burn)
  anchorNonce: text("anchor_nonce"), // Anchor nonce for decrypting manifestCid
  locations: jsonb("locations").notNull(), // Array of location data with blockchain proof
  metadata: jsonb("metadata"), // Optional: note, photo IPFS CID
  deviceAttested: boolean("device_attested").default(false), // Hardware device attestation status
  deviceId: varchar("device_id", { length: 64 }), // Unique device identifier (optional)
  platform: varchar("platform", { length: 10 }), // "ios" or "android" (optional)
  userFirstName: varchar("user_first_name", { length: 255 }), // User's first name (optional)
  userLastName: varchar("user_last_name", { length: 255 }), // User's last name (optional)
  createdAt: timestamp("created_at").default(sql`NOW()`),
  expiresAt: timestamp("expires_at"), // Optional expiration
  viewCount: integer("view_count").default(0),
  isPublished: boolean("is_published").default(true), // Whether the proof page is publicly accessible
  passwordHash: text("password_hash"), // bcrypt hash of password for protected proofs
});

// Witness invitations table (for proof attestations)
export const witnessInvitations = pgTable("witness_invitations", {
  id: serial("id").primaryKey(),
  invitationId: varchar("invitation_id", { length: 32 }).notNull().unique(), // Unique ID (e.g., inv_abc123xyz)
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull(), // Links witness to specific proof
  anchorTimestamp: bigint("anchor_timestamp", { mode: "number" }).notNull(), // Unix timestamp (ms)
  proofId: uuid("proof_id"), // Optional: links to public proof if one exists
  userName: varchar("user_name", { length: 255 }), // Name of user who invited witness
  witnessEmail: varchar("witness_email", { length: 255 }), // Optional for direct share invitations
  witnessName: varchar("witness_name", { length: 255 }).notNull(), // Full name of the witness
  locationDetails: jsonb("location_details").notNull(), // { timestamp, latitude, longitude, accuracy }
  invitationMethod: varchar("invitation_method", { length: 20 }).default("email"), // 'email' or 'direct_share'
  status: varchar("status", { length: 20 }).default("pending"), // pending, accepted, declined
  signatureType: varchar("signature_type", { length: 10 }), // 'drawn' or 'typed'
  signatureData: text("signature_data"), // Base64 PNG for drawn, or typed name
  pdfCid: text("pdf_cid"), // IPFS CID of the signed attestation PDF
  pdfRegistryTxHash: text("pdf_registry_tx_hash"), // Transaction hash from PDFRegistry contract
  signedDocumentUrl: text("signed_document_url"), // Deprecated (HelloSign URL from Make.com)
  sentAt: timestamp("sent_at").default(sql`NOW()`),
  respondedAt: timestamp("responded_at"),
  linkOpenedAt: timestamp("link_opened_at"), // When the witness opened the invitation link (for direct_share QR code hiding)
});

// Dispute analyses table (Forensic AI detection results)
export const disputeAnalyses = pgTable("dispute_analyses", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: integer("user_id").references(() => userAccounts.id, { onDelete: 'cascade' }), // Nullable for test token scenarios
  imageCid: varchar("image_cid", { length: 100 }).notNull(),
  claimedDate: date("claimed_date"),
  isLikelyAiGenerated: boolean("is_likely_ai_generated"),
  confidenceScore: text("confidence_score"), // Store as string for decimal precision
  confidenceLevel: varchar("confidence_level", { length: 20 }), // 'low' | 'medium' | 'high' | 'very_high'
  sightengineResponse: jsonb("sightengine_response").notNull(),
  illuminartyResponse: jsonb("illuminarty_response"), // Future integration
  hasExifData: boolean("has_exif_data"),
  suspiciousFlags: text("suspicious_flags").array(),
  extractedMetadata: jsonb("extracted_metadata"),
  analyzedAt: timestamp("analyzed_at", { withTimezone: true }).default(sql`NOW()`),
});

// Image disputes attached table (Mode 1 - attached to anchors)
export const imageDisputesAttached = pgTable("image_disputes_attached", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: integer("user_id").references(() => userAccounts.id, { onDelete: 'cascade' }), // Nullable for test token scenarios
  analysisId: uuid("analysis_id").notNull().references(() => disputeAnalyses.id, { onDelete: 'cascade' }),
  anchorAddress: varchar("anchor_address", { length: 66 }).notNull().unique(), // One dispute per anchor
  anchorTimestamp: timestamp("anchor_timestamp", { withTimezone: true }).notNull(),
  manifestCid: varchar("manifest_cid", { length: 100 }).notNull(),
  imageCid: varchar("image_cid", { length: 100 }).notNull(),
  userStatement: text("user_statement"),
  claimedDate: date("claimed_date").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).default(sql`NOW()`),
  updatedAt: timestamp("updated_at", { withTimezone: true }).default(sql`NOW()`),
});

// Image disputes standalone table (Mode 2 - standalone reports)
export const imageDisputesStandalone = pgTable("image_disputes_standalone", {
  id: uuid("id").primaryKey().default(sql`gen_random_uuid()`),
  userId: integer("user_id").references(() => userAccounts.id, { onDelete: 'cascade' }), // Nullable for test token scenarios
  analysisId: uuid("analysis_id").notNull().references(() => disputeAnalyses.id, { onDelete: 'cascade' }),
  imageCid: varchar("image_cid", { length: 100 }).notNull(),
  userStatement: text("user_statement"),
  claimedDate: date("claimed_date").notNull(),
  isPublished: boolean("is_published").default(true),
  passwordHash: text("password_hash"),
  createdAt: timestamp("created_at", { withTimezone: true }).default(sql`NOW()`),
  updatedAt: timestamp("updated_at", { withTimezone: true }).default(sql`NOW()`),
});

// Relations
export const userAccountsRelations = relations(userAccounts, ({ many }) => ({
  ownershipProofs: many(ownershipProofs),
  proofRequests: many(proofRequests),
  publicProofs: many(publicProofs),
  devices: many(devices),
  passkeyChallenges: many(passkeyChallenges),
  disputeAnalyses: many(disputeAnalyses),
  imageDisputesAttached: many(imageDisputesAttached),
  imageDisputesStandalone: many(imageDisputesStandalone),
}));

export const disputeAnalysesRelations = relations(disputeAnalyses, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [disputeAnalyses.userId],
    references: [userAccounts.id],
  }),
}));

export const imageDisputesAttachedRelations = relations(imageDisputesAttached, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [imageDisputesAttached.userId],
    references: [userAccounts.id],
  }),
  disputeAnalysis: one(disputeAnalyses, {
    fields: [imageDisputesAttached.analysisId],
    references: [disputeAnalyses.id],
  }),
}));

export const imageDisputesStandaloneRelations = relations(imageDisputesStandalone, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [imageDisputesStandalone.userId],
    references: [userAccounts.id],
  }),
  disputeAnalysis: one(disputeAnalyses, {
    fields: [imageDisputesStandalone.analysisId],
    references: [disputeAnalyses.id],
  }),
}));

export const devicesRelations = relations(devices, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [devices.userId],
    references: [userAccounts.id],
  }),
}));

export const passkeyChallengesRelations = relations(passkeyChallenges, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [passkeyChallenges.userId],
    references: [userAccounts.id],
  }),
}));

export const ownershipProofsRelations = relations(ownershipProofs, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [ownershipProofs.masterAddress],
    references: [userAccounts.masterAddress],
  }),
}));

// Zod schemas
export const insertUserAccountSchema = createInsertSchema(userAccounts).omit({
  id: true,
  createdAt: true,
  lastActive: true,
  activeDeviceId: true,
  activeSessionId: true,
  lastLoginAt: true,
}).extend({
  clerkUserId: z.string().optional(),
  walletAddress: z.string().optional(),
  authType: z.enum(['clerk', 'world_wallet']).default('clerk'),
});

export const insertOwnershipProofSchema = createInsertSchema(ownershipProofs).omit({
  id: true,
  proofTimestamp: true,
});

export const insertProofRequestSchema = createInsertSchema(proofRequests).omit({
  id: true,
  createdAt: true,
});

export const insertPublicProofSchema = createInsertSchema(publicProofs).omit({
  id: true,
  createdAt: true,
  viewCount: true,
});

export const insertDeviceAttestationSchema = createInsertSchema(deviceAttestations).omit({
  id: true,
  verifiedAt: true,
});

export const insertWitnessInvitationSchema = createInsertSchema(witnessInvitations).omit({
  id: true,
  sentAt: true,
  respondedAt: true,
});

export const insertBurnedAnchorSchema = createInsertSchema(burnedAnchors).omit({
  id: true,
  burnedAt: true,
});

export const insertDeviceSchema = createInsertSchema(devices).omit({
  id: true,
  createdAt: true,
  lastSeenAt: true,
  revokedAt: true,
});

// Subscription tier update schema
export const updateSubscriptionTierSchema = z.object({
  subscriptionTier: z.enum(['free', 'paid']),
});

export type UpdateSubscriptionTier = z.infer<typeof updateSubscriptionTierSchema>;

export const insertPasskeyChallengeSchema = createInsertSchema(passkeyChallenges).omit({
  id: true,
  createdAt: true,
});

export const insertDisputeAnalysisSchema = createInsertSchema(disputeAnalyses).omit({
  id: true,
  analyzedAt: true,
});

export const insertImageDisputeAttachedSchema = createInsertSchema(imageDisputesAttached).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertImageDisputeStandaloneSchema = createInsertSchema(imageDisputesStandalone).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

// Types
export type UserAccount = typeof userAccounts.$inferSelect;
export type InsertUserAccount = z.infer<typeof insertUserAccountSchema>;
export type OwnershipProof = typeof ownershipProofs.$inferSelect;
export type InsertOwnershipProof = z.infer<typeof insertOwnershipProofSchema>;
export type ProofRequest = typeof proofRequests.$inferSelect;
export type InsertProofRequest = z.infer<typeof insertProofRequestSchema>;
export type PublicProof = typeof publicProofs.$inferSelect;
export type InsertPublicProof = z.infer<typeof insertPublicProofSchema>;
export type DeviceAttestation = typeof deviceAttestations.$inferSelect;
export type InsertDeviceAttestation = z.infer<typeof insertDeviceAttestationSchema>;
export type WitnessInvitation = typeof witnessInvitations.$inferSelect;
export type InsertWitnessInvitation = z.infer<typeof insertWitnessInvitationSchema>;
export type BurnedAnchor = typeof burnedAnchors.$inferSelect;
export type InsertBurnedAnchor = z.infer<typeof insertBurnedAnchorSchema>;
export type Device = typeof devices.$inferSelect;
export type InsertDevice = z.infer<typeof insertDeviceSchema>;
export type PasskeyChallenge = typeof passkeyChallenges.$inferSelect;
export type InsertPasskeyChallenge = z.infer<typeof insertPasskeyChallengeSchema>;
export type DisputeAnalysis = typeof disputeAnalyses.$inferSelect;
export type InsertDisputeAnalysis = z.infer<typeof insertDisputeAnalysisSchema>;
export type ImageDisputeAttached = typeof imageDisputesAttached.$inferSelect;
export type InsertImageDisputeAttached = z.infer<typeof insertImageDisputeAttachedSchema>;
export type ImageDisputeStandalone = typeof imageDisputesStandalone.$inferSelect;
export type InsertImageDisputeStandalone = z.infer<typeof insertImageDisputeStandaloneSchema>;


// Blockchain indexer tables (replaces The Graph Studio)
export const indexedLocationAnchors = pgTable("indexed_location_anchors", {
  id: serial("id").primaryKey(),
  chain: varchar("chain", { length: 50 }).notNull(), // "arbitrum-sepolia" or "world-chain-sepolia"
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull(),
  masterAddress: varchar("master_address", { length: 42 }), // V4.5: Master address for recovery queries
  recoveryHint: varchar("recovery_hint", { length: 66 }), // V3.5.0 privacy-preserving
  timestamp: text("timestamp").notNull(), // ISO 8601 from contract event
  manifestCid: text("manifest_cid").notNull(),
  anchorNonce: varchar("anchor_nonce", { length: 78 }).notNull(), // uint256 as string
  deviceAttested: boolean("device_attested").notNull().default(false),
  blockNumber: bigint("block_number", { mode: "number" }).notNull(),
  blockTimestamp: bigint("block_timestamp", { mode: "number" }).notNull(), // Unix timestamp
  transactionHash: varchar("transaction_hash", { length: 66 }).notNull().unique(),
  anchorPublicKey: text("anchor_public_key"), // V5.2: Recovered public key from anchor signature (for ECIES encryption)
  indexed_at: timestamp("indexed_at").default(sql`NOW()`),
}, (table) => ({
  anchorChainIdx: sql`CREATE INDEX IF NOT EXISTS idx_anchor_chain ON ${table} (anchor_address, chain)`,
  recoveryHintIdx: sql`CREATE INDEX IF NOT EXISTS idx_recovery_hint ON ${table} (recovery_hint)`,
  masterAddressIdx: sql`CREATE INDEX IF NOT EXISTS idx_master_address ON ${table} (master_address, chain)`,
  masterTimestampIdx: sql`CREATE INDEX IF NOT EXISTS idx_master_timestamp ON ${table} (master_address, block_timestamp DESC)`,
}));

export const indexedOwnershipProofs = pgTable("indexed_ownership_proofs", {
  id: serial("id").primaryKey(),
  chain: varchar("chain", { length: 50 }).notNull(),
  masterAddress: varchar("master_address", { length: 42 }).notNull(),
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull(),
  proofHash: varchar("proof_hash", { length: 66 }).notNull().unique(),
  blockNumber: bigint("block_number", { mode: "number" }).notNull(),
  blockTimestamp: bigint("block_timestamp", { mode: "number" }).notNull(),
  transactionHash: varchar("transaction_hash", { length: 66 }).notNull().unique(),
  indexed_at: timestamp("indexed_at").default(sql`NOW()`),
}, (table) => ({
  masterIdx: sql`CREATE INDEX IF NOT EXISTS idx_master ON ${table} (master_address)`,
  anchorIdx: sql`CREATE INDEX IF NOT EXISTS idx_anchor ON ${table} (anchor_address)`,
}));

export const indexedAnchorBurns = pgTable("indexed_anchor_burns", {
  id: serial("id").primaryKey(),
  chain: varchar("chain", { length: 50 }).notNull(),
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull(),
  proofHash: varchar("proof_hash", { length: 66 }).notNull(),
  blockNumber: bigint("block_number", { mode: "number" }).notNull(),
  blockTimestamp: bigint("block_timestamp", { mode: "number" }).notNull(),
  transactionHash: varchar("transaction_hash", { length: 66 }).notNull().unique(),
  indexed_at: timestamp("indexed_at").default(sql`NOW()`),
}, (table) => ({
  anchorIdx: sql`CREATE INDEX IF NOT EXISTS idx_burn_anchor ON ${table} (anchor_address)`,
}));

export const insertIndexedLocationAnchorSchema = createInsertSchema(indexedLocationAnchors).omit({
  id: true,
  indexed_at: true,
});

export const insertIndexedOwnershipProofSchema = createInsertSchema(indexedOwnershipProofs).omit({
  id: true,
  indexed_at: true,
});

export const insertIndexedAnchorBurnSchema = createInsertSchema(indexedAnchorBurns).omit({
  id: true,
  indexed_at: true,
});

export type IndexedLocationAnchor = typeof indexedLocationAnchors.$inferSelect;
export type InsertIndexedLocationAnchor = z.infer<typeof insertIndexedLocationAnchorSchema>;
export type IndexedOwnershipProof = typeof indexedOwnershipProofs.$inferSelect;
export type InsertIndexedOwnershipProof = z.infer<typeof insertIndexedOwnershipProofSchema>;
export type IndexedAnchorBurn = typeof indexedAnchorBurns.$inferSelect;
export type InsertIndexedAnchorBurn = z.infer<typeof insertIndexedAnchorBurnSchema>;

// Anchor Public Keys table (V5.2 - for ECIES encryption of PDF CIDs)
export const anchorPublicKeys = pgTable("anchor_public_keys", {
  id: serial("id").primaryKey(),
  anchorAddress: varchar("anchor_address", { length: 42 }).notNull().unique(),
  publicKey: text("public_key").notNull(), // Uncompressed public key (0x04...)
  createdAt: timestamp("created_at").default(sql`NOW()`),
});

export const insertAnchorPublicKeySchema = createInsertSchema(anchorPublicKeys).omit({
  id: true,
  createdAt: true,
});

export type AnchorPublicKey = typeof anchorPublicKeys.$inferSelect;
export type InsertAnchorPublicKey = z.infer<typeof insertAnchorPublicKeySchema>;

// GDPR Audit Logs table - tracks data deletion and export requests for compliance
export const gdprAuditLogs = pgTable("gdpr_audit_logs", {
  id: serial("id").primaryKey(),
  deletionId: varchar("deletion_id", { length: 64 }).notNull().unique(), // Unique identifier for the request
  actionType: varchar("action_type", { length: 20 }).notNull(), // 'deletion' or 'export'
  
  // Searchable user info (stored for audit trail even after deletion)
  userName: text("user_name"), // User's name at time of request
  userEmail: text("user_email"), // User's email at time of request
  userIdHash: varchar("user_id_hash", { length: 64 }), // Hashed user ID for privacy
  masterAddress: varchar("master_address", { length: 42 }), // User's wallet address
  
  // Request details
  status: varchar("status", { length: 20 }).notNull().default("completed"), // 'pending', 'completed', 'failed'
  requestedAt: timestamp("requested_at").default(sql`NOW()`),
  completedAt: timestamp("completed_at"),
  
  // Deletion-specific data
  tablesAffected: text("tables_affected"), // Comma-separated list
  deletionCounts: jsonb("deletion_counts"), // { witnessInvitations: 2, devices: 1, ... }
  
  // Export-specific data
  exportSentTo: text("export_sent_to"), // Masked email where export was sent
  
  // Metadata
  ipAddress: varchar("ip_address", { length: 45 }), // IPv4 or IPv6
  userAgent: text("user_agent"),
  notes: text("notes"), // Any additional notes
  
  createdAt: timestamp("created_at").default(sql`NOW()`),
});

export const insertGdprAuditLogSchema = createInsertSchema(gdprAuditLogs).omit({
  id: true,
  createdAt: true,
});

export type GdprAuditLog = typeof gdprAuditLogs.$inferSelect;
export type InsertGdprAuditLog = z.infer<typeof insertGdprAuditLogSchema>;

// Support requests table - public support form submissions
export const supportRequests = pgTable("support_requests", {
  id: serial("id").primaryKey(),
  fullName: varchar("full_name", { length: 255 }).notNull(),
  email: varchar("email", { length: 255 }).notNull(),
  mobileDevice: varchar("mobile_device", { length: 20 }).notNull(), // 'iphone', 'android', 'other'
  message: text("message").notNull(),
  screenshotUrl: text("screenshot_url"), // Optional file URL
  status: varchar("status", { length: 20 }).default("new"), // 'new', 'in_progress', 'resolved'
  createdAt: timestamp("created_at").default(sql`NOW()`),
});

export const insertSupportRequestSchema = createInsertSchema(supportRequests).omit({
  id: true,
  createdAt: true,
  status: true,
});

export type SupportRequest = typeof supportRequests.$inferSelect;
export type InsertSupportRequest = z.infer<typeof insertSupportRequestSchema>;

// Email preferences and onboarding tracking table
export const emailPreferences = pgTable("email_preferences", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => userAccounts.id, { onDelete: 'cascade' }).unique(),
  
  // Email subscription preferences
  unsubscribedFromAll: boolean("unsubscribed_from_all").default(false),
  unsubscribedFromOnboarding: boolean("unsubscribed_from_onboarding").default(false),
  unsubscribedFromMonthlyRecap: boolean("unsubscribed_from_monthly_recap").default(false),
  unsubscribeToken: varchar("unsubscribe_token", { length: 64 }).notNull().unique(), // For one-click unsubscribe links
  
  // Onboarding email sequence tracking (sent timestamps)
  onboardingEmail1SentAt: timestamp("onboarding_email_1_sent_at"), // 24h after signup + first anchor
  onboardingEmail2SentAt: timestamp("onboarding_email_2_sent_at"), // 4 days after signup
  onboardingEmail3SentAt: timestamp("onboarding_email_3_sent_at"), // 6 days after signup
  onboardingEmail4SentAt: timestamp("onboarding_email_4_sent_at"), // 7 days after signup
  onboardingEmail5SentAt: timestamp("onboarding_email_5_sent_at"), // 13 days after signup
  
  // Monthly recap tracking
  lastMonthlyRecapSentAt: timestamp("last_monthly_recap_sent_at"),
  lastMonthlyRecapMonth: varchar("last_monthly_recap_month", { length: 7 }), // Format: "YYYY-MM"
  
  createdAt: timestamp("created_at").default(sql`NOW()`),
  updatedAt: timestamp("updated_at").default(sql`NOW()`),
});

export const emailPreferencesRelations = relations(emailPreferences, ({ one }) => ({
  userAccount: one(userAccounts, {
    fields: [emailPreferences.userId],
    references: [userAccounts.id],
  }),
}));

export const insertEmailPreferencesSchema = createInsertSchema(emailPreferences).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export type EmailPreferences = typeof emailPreferences.$inferSelect;
export type InsertEmailPreferences = z.infer<typeof insertEmailPreferencesSchema>;

// Market data cache table - persists API data across server restarts
export const marketDataCache = pgTable("market_data_cache", {
  id: serial("id").primaryKey(),
  cacheKey: varchar("cache_key", { length: 50 }).notNull().unique(), // e.g., 'market_data'
  data: jsonb("data").notNull(), // The cached market data JSON
  lastUpdated: timestamp("last_updated").default(sql`NOW()`).notNull(),
  createdAt: timestamp("created_at").default(sql`NOW()`),
});

export const insertMarketDataCacheSchema = createInsertSchema(marketDataCache).omit({
  id: true,
  createdAt: true,
});

export type MarketDataCache = typeof marketDataCache.$inferSelect;
export type InsertMarketDataCache = z.infer<typeof insertMarketDataCacheSchema>;
