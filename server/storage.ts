import { drizzle } from 'drizzle-orm/neon-serverless';
import { neon } from '@neondatabase/serverless';
import { eq, sql as sqlTag } from 'drizzle-orm';
import { publicProofs } from '../shared/schema.js';

// Initialize Neon connection
const sql = neon(process.env.DATABASE_URL!);
export const db = drizzle({ client: sql as any });

export const storage = {
  async getPublicProof(proofId: string) {
    try {
      const results = await db.select().from(publicProofs).where(eq(publicProofs.proofId, proofId));
      return results[0] || null;
    } catch (error) {
      console.error('[Storage] Error fetching public proof:', error);
      return null;
    }
  },

  async incrementProofViewCount(proofId: string) {
    try {
      await db.update(publicProofs)
        .set({ viewCount: sqlTag`COALESCE(${publicProofs.viewCount}, 0) + 1` })
        .where(eq(publicProofs.proofId, proofId));
    } catch (error) {
      console.error('[Storage] Error incrementing view count:', error);
    }
  },

  async createPublicProof(data: {
    proofId: string;
    masterAddress: string;
    anchorAddresses: string[];
    locations: any;
    metadata?: any;
    deviceAttested?: boolean;
    deviceId?: string;
    platform?: string;
    userFirstName?: string;
    userLastName?: string;
    anchorPrivateKey?: string;
    anchorNonce?: string;
    expiresAt?: Date;
  }) {
    try {
      const [result] = await db.insert(publicProofs).values({
        proofId: data.proofId,
        masterAddress: data.masterAddress,
        anchorAddresses: data.anchorAddresses,
        locations: data.locations,
        metadata: data.metadata || {},
        deviceAttested: data.deviceAttested || false,
        deviceId: data.deviceId,
        platform: data.platform,
        userFirstName: data.userFirstName,
        userLastName: data.userLastName,
        anchorPrivateKey: data.anchorPrivateKey,
        anchorNonce: data.anchorNonce,
        expiresAt: data.expiresAt
      }).returning();
      return result;
    } catch (error) {
      console.error('[Storage] Error creating public proof:', error);
      throw error;
    }
  }
};
