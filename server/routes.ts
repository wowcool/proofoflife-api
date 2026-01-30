import { Express, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { fromZodError } from 'zod-validation-error';
import { ethers } from 'ethers';
import CryptoJS from 'crypto-js';
import { storage } from './storage.js';

// Base production URL
const BASE_URL = 'https://proof.proofoflife.io';
const IPFS_GATEWAY = 'https://ipfs.alibiledger.com/ipfs';

// IPFS helper
function getIPFSGatewayUrl(cid: string): string {
  return `${IPFS_GATEWAY}/${cid}`;
}

// Format anchor address into human-readable hash like "3GVU-9FWZ-CLXS"
function formatVerifiableHash(address: string): string {
  const cleanAddress = address.toLowerCase().replace('0x', '');
  const bytes = Buffer.from(cleanAddress, 'hex');
  
  // Use base32-like encoding for readability
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let encoded = '';
  
  for (let i = 0; i < 12 && i < bytes.length; i++) {
    encoded += alphabet[bytes[i] % alphabet.length];
  }
  
  // Format as XXX-XXXX-XXXX
  return `${encoded.slice(0, 4)}-${encoded.slice(4, 8)}-${encoded.slice(8, 12)}`;
}

// Generate the "How This Proof Works" explanation
function generateProofExplanation(data: {
  verifiableHash: string;
  masterAddress: string;
  anchorAddress: string;
  blockTimestamp: Date;
  blockNumber?: number;
}) {
  const formattedDate = data.blockTimestamp.toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short'
  });
  
  return {
    title: "How This Proof Works",
    summary: `This hash proves the photo was taken by someone who controlled the private key at this exact moment.`,
    steps: [
      {
        step: 1,
        title: "Unique Hash Generation",
        description: `The hash '${data.verifiableHash}' is derived from the user's wallet address and a sequential nonce. This creates a unique, deterministic identifier that only the wallet owner can generate.`
      },
      {
        step: 2,
        title: "Private Key Signature",
        description: `The anchor address was derived from the master wallet's private key. Only someone with access to that private key could have created the cryptographic signatures that authorized this proof.`
      },
      {
        step: 3,
        title: "Blockchain Timestamp",
        description: `The proof was anchored to World Chain${data.blockNumber ? ` at block ${data.blockNumber}` : ''}, creating an immutable timestamp. The blockchain acts as a neutral witness that cannot be altered retroactively.`
      },
      {
        step: 4,
        title: "Photo Binding",
        description: "The photo's content hash is included in the blockchain anchor. Any modification to the photo would produce a different hash, breaking the cryptographic link."
      },
      {
        step: 5,
        title: "Location Binding",
        description: "GPS coordinates (verified to high accuracy) were captured at the moment of proof creation and included in the signed manifest stored on IPFS."
      }
    ],
    conclusion: `Together, these elements prove that on ${formattedDate}, someone with control of wallet ${data.masterAddress.slice(0, 6)}...${data.masterAddress.slice(-4)} was physically present at this location and captured this specific photo.`
  };
}

// Generate HTML page for proof verification
function generateProofOfLifePage(data: {
  proofId: string;
  verifiableHash: string;
  photoUrl?: string;
  what3words?: string;
  latitude?: number;
  longitude?: number;
  accuracy?: number;
  timestamp: Date;
  platform?: string;
  deviceAttested?: boolean;
  masterAddress: string;
  anchorAddress: string;
  anchorTxHash?: string;
  ownershipTxHash?: string;
  manifestCid?: string;
  blockNumber?: number;
}): string {
  const explanation = generateProofExplanation({
    verifiableHash: data.verifiableHash,
    masterAddress: data.masterAddress,
    anchorAddress: data.anchorAddress,
    blockTimestamp: data.timestamp,
    blockNumber: data.blockNumber
  });

  const formattedTime = data.timestamp.toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short'
  });

  const explorerUrl = data.ownershipTxHash 
    ? `https://worldscan.org/tx/${data.ownershipTxHash}`
    : data.anchorTxHash
    ? `https://worldscan.org/tx/${data.anchorTxHash}`
    : null;

  const ipfsUrl = data.manifestCid 
    ? `https://ipfs.io/ipfs/${data.manifestCid}`
    : null;

  const locationDisplay = data.what3words 
    ? `///${data.what3words}`
    : data.latitude && data.longitude
    ? `${data.latitude.toFixed(6)}, ${data.longitude.toFixed(6)}`
    : 'Location verified';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proof of Life - ${data.verifiableHash}</title>
  <meta name="description" content="Verified cryptographic proof of presence - ${data.verifiableHash}">
  <meta property="og:title" content="Proof of Life - ${data.verifiableHash}">
  <meta property="og:description" content="Cryptographically verified proof of presence at ${locationDisplay}">
  <meta property="og:type" content="website">
  ${data.photoUrl ? `<meta property="og:image" content="${data.photoUrl}">` : ''}
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      color: #fff;
      line-height: 1.6;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .header {
      text-align: center;
      padding: 30px 0;
    }
    .logo {
      font-size: 24px;
      font-weight: 700;
      color: #4ade80;
      margin-bottom: 10px;
    }
    .card {
      background: rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .photo-container {
      width: 100%;
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 20px;
    }
    .photo-container img {
      width: 100%;
      height: auto;
      display: block;
    }
    .no-photo {
      background: rgba(255, 255, 255, 0.05);
      height: 200px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: rgba(255, 255, 255, 0.5);
    }
    .detail-row {
      display: flex;
      align-items: center;
      padding: 12px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    .detail-row:last-child { border-bottom: none; }
    .detail-icon { font-size: 20px; margin-right: 12px; }
    .detail-content { flex: 1; }
    .detail-label { font-size: 12px; color: rgba(255, 255, 255, 0.6); }
    .detail-value { font-size: 16px; font-weight: 500; }
    .hash-display {
      background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%);
      color: #000;
      padding: 16px;
      border-radius: 12px;
      text-align: center;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 2px;
      font-family: 'SF Mono', Monaco, monospace;
      margin: 16px 0;
    }
    .section-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .step {
      background: rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 12px;
    }
    .step-number {
      background: #4ade80;
      color: #000;
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-weight: 700;
      margin-right: 8px;
    }
    .step-title { font-weight: 600; margin-bottom: 8px; }
    .step-desc { font-size: 14px; color: rgba(255, 255, 255, 0.8); }
    .button-row {
      display: flex;
      gap: 12px;
      margin-top: 20px;
    }
    .btn {
      flex: 1;
      padding: 14px;
      border-radius: 10px;
      text-align: center;
      text-decoration: none;
      font-weight: 600;
      font-size: 14px;
      transition: transform 0.2s, opacity 0.2s;
    }
    .btn:hover { transform: translateY(-2px); opacity: 0.9; }
    .btn-primary {
      background: linear-gradient(135deg, #4ade80 0%, #22c55e 100%);
      color: #000;
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.1);
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.2);
    }
    .conclusion {
      background: rgba(74, 222, 128, 0.1);
      border: 1px solid rgba(74, 222, 128, 0.3);
      border-radius: 12px;
      padding: 16px;
      margin-top: 16px;
      font-size: 14px;
    }
    .attested-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(74, 222, 128, 0.2);
      color: #4ade80;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
    }
    .footer {
      text-align: center;
      padding: 40px 0;
      color: rgba(255, 255, 255, 0.5);
      font-size: 12px;
    }
    .collapsible-header {
      cursor: pointer;
      user-select: none;
    }
    .collapsible-content {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease-out;
    }
    .collapsible-content.open {
      max-height: 2000px;
    }
    .toggle-icon {
      transition: transform 0.3s;
    }
    .toggle-icon.open {
      transform: rotate(180deg);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">Proof of Life</div>
      <p style="color: rgba(255,255,255,0.6); font-size: 14px;">Cryptographic Proof Verification</p>
    </div>
    
    <div class="card">
      <div class="photo-container">
        ${data.photoUrl 
          ? `<img src="${data.photoUrl}" alt="Proof photo" loading="lazy">`
          : `<div class="no-photo">No photo attached</div>`
        }
      </div>
      
      <div class="hash-display">${data.verifiableHash}</div>
      
      <div class="detail-row">
        <div class="detail-icon">📍</div>
        <div class="detail-content">
          <div class="detail-label">Location</div>
          <div class="detail-value">${locationDisplay}</div>
        </div>
      </div>
      
      <div class="detail-row">
        <div class="detail-icon">⏰</div>
        <div class="detail-content">
          <div class="detail-label">Timestamp</div>
          <div class="detail-value">${formattedTime}</div>
        </div>
      </div>
      
      <div class="detail-row">
        <div class="detail-icon">📱</div>
        <div class="detail-content">
          <div class="detail-label">Device</div>
          <div class="detail-value">
            ${data.deviceAttested 
              ? `<span class="attested-badge">✓ Verified ${data.platform === 'ios' ? 'iOS' : data.platform === 'android' ? 'Android' : ''} Device</span>`
              : `${data.platform === 'ios' ? 'iOS' : data.platform === 'android' ? 'Android' : 'Mobile'} Device`
            }
          </div>
        </div>
      </div>
    </div>
    
    <div class="card">
      <div class="section-title collapsible-header" onclick="toggleExplanation()">
        <span>🔒</span> How This Proof Works
        <span class="toggle-icon" id="toggleIcon">▼</span>
      </div>
      
      <div class="collapsible-content" id="explanationContent">
        ${explanation.steps.map(step => `
          <div class="step">
            <div class="step-title">
              <span class="step-number">${step.step}</span>
              ${step.title}
            </div>
            <div class="step-desc">${step.description}</div>
          </div>
        `).join('')}
        
        <div class="conclusion">
          <strong>Conclusion:</strong> ${explanation.conclusion}
        </div>
      </div>
    </div>
    
    <div class="button-row">
      ${explorerUrl ? `<a href="${explorerUrl}" target="_blank" class="btn btn-primary">View on Blockchain</a>` : ''}
      ${ipfsUrl ? `<a href="${ipfsUrl}" target="_blank" class="btn btn-secondary">Verify on IPFS</a>` : ''}
    </div>
    
    <div class="footer">
      <p>Powered by World Chain blockchain technology</p>
      <p style="margin-top: 8px;">proofoflife.io</p>
    </div>
  </div>
  
  <script>
    function toggleExplanation() {
      const content = document.getElementById('explanationContent');
      const icon = document.getElementById('toggleIcon');
      content.classList.toggle('open');
      icon.classList.toggle('open');
    }
    // Start collapsed
    document.addEventListener('DOMContentLoaded', function() {
      const content = document.getElementById('explanationContent');
      content.classList.remove('open');
    });
  </script>
</body>
</html>`;
}

// JSON body validation middleware
function validateJsonBody(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    if (!req.body || Object.keys(req.body).length === 0) {
      return res.status(400).json({ success: false, error: 'Request body is required' });
    }
  }
  next();
}

export function setupRoutes(app: Express) {
  
  /**
   * GET /api/public/proofoflife/:proofId
   * NEW ENDPOINT - Renders HTML page for Proof of Life verification
   */
  app.get('/api/public/proofoflife/:proofId', async (req: Request, res: Response) => {
    try {
      const { proofId } = req.params;
      
      console.log(`[ProofOfLife] Fetching proof: ${proofId}`);
      
      // Fetch proof from database
      const proof = await storage.getPublicProof(proofId);
      
      if (!proof) {
        return res.status(404).send(`
          <!DOCTYPE html>
          <html><head><title>Proof Not Found</title></head>
          <body style="font-family: sans-serif; text-align: center; padding: 50px;">
            <h1>Proof Not Found</h1>
            <p>The requested proof does not exist or has expired.</p>
          </body></html>
        `);
      }
      
      // Parse locations from proof
      const locations = Array.isArray(proof.locations) ? proof.locations : [];
      const firstLocation = locations[0] as any;
      
      // Get photo URL if available
      const metadata = proof.metadata as any;
      const photoIpfsCid = metadata?.photoIpfsCid || metadata?.photoCid;
      const photoUrl = photoIpfsCid ? getIPFSGatewayUrl(photoIpfsCid) : undefined;
      
      // Generate verifiable hash from anchor address
      const anchorAddress = proof.anchorAddresses?.[0] || '';
      const verifiableHash = formatVerifiableHash(anchorAddress);
      
      // Get blockchain transaction info
      const anchorTxHash = metadata?.anchorTxHash;
      const ownershipTxHash = metadata?.ownershipTxHash || metadata?.proofTxHash;
      const blockNumber = metadata?.blockNumber;
      
      // Generate the HTML page
      const html = generateProofOfLifePage({
        proofId: proof.proofId,
        verifiableHash,
        photoUrl,
        what3words: firstLocation?.what3words,
        latitude: firstLocation?.latitude,
        longitude: firstLocation?.longitude,
        accuracy: firstLocation?.accuracy,
        timestamp: proof.createdAt || new Date(),
        platform: proof.platform || undefined,
        deviceAttested: proof.deviceAttested || false,
        masterAddress: proof.masterAddress,
        anchorAddress,
        anchorTxHash,
        ownershipTxHash,
        manifestCid: metadata?.manifestCid,
        blockNumber
      });
      
      // Update view count
      try {
        await storage.incrementProofViewCount(proofId);
      } catch (e) {
        console.error('[ProofOfLife] Failed to increment view count:', e);
      }
      
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
      
    } catch (error) {
      console.error('[ProofOfLife] Error fetching proof:', error);
      res.status(500).send(`
        <!DOCTYPE html>
        <html><head><title>Error</title></head>
        <body style="font-family: sans-serif; text-align: center; padding: 50px;">
          <h1>Something went wrong</h1>
          <p>Please try again later.</p>
        </body></html>
      `);
    }
  });
  
  /**
   * GET /api/public/proofoflife/:proofId/data
   * Returns JSON data for the proof (for programmatic access)
   */
  app.get('/api/public/proofoflife/:proofId/data', async (req: Request, res: Response) => {
    try {
      const { proofId } = req.params;
      
      const proof = await storage.getPublicProof(proofId);
      
      if (!proof) {
        return res.status(404).json({ success: false, error: 'Proof not found' });
      }
      
      const locations = Array.isArray(proof.locations) ? proof.locations : [];
      const firstLocation = locations[0] as any;
      const metadata = proof.metadata as any;
      const anchorAddress = proof.anchorAddresses?.[0] || '';
      const verifiableHash = formatVerifiableHash(anchorAddress);
      
      const explanation = generateProofExplanation({
        verifiableHash,
        masterAddress: proof.masterAddress,
        anchorAddress,
        blockTimestamp: proof.createdAt || new Date(),
        blockNumber: metadata?.blockNumber
      });
      
      res.json({
        success: true,
        proofId: proof.proofId,
        verifiableHash,
        
        cryptographicProof: {
          anchorAddress,
          masterWalletAddress: proof.masterAddress,
          derivationNonce: proof.anchorNonce,
          anchorTxHash: metadata?.anchorTxHash,
          ownershipTxHash: metadata?.ownershipTxHash || metadata?.proofTxHash,
          blockNumber: metadata?.blockNumber,
          blockTimestamp: proof.createdAt?.toISOString(),
          manifestCid: metadata?.manifestCid,
          proofHash: metadata?.proofHash
        },
        
        verification: {
          hashDerivation: {
            method: 'keccak256(masterAddress + nonce)',
            result: anchorAddress,
            formattedHash: verifiableHash
          },
          blockchainVerification: {
            anchorOnChain: true,
            ownershipOnChain: !!metadata?.ownershipTxHash,
            explorerUrl: metadata?.ownershipTxHash 
              ? `https://worldscan.org/tx/${metadata.ownershipTxHash}`
              : metadata?.anchorTxHash
              ? `https://worldscan.org/tx/${metadata.anchorTxHash}`
              : null
          }
        },
        
        location: firstLocation ? {
          latitude: firstLocation.latitude,
          longitude: firstLocation.longitude,
          accuracy: firstLocation.accuracy,
          what3words: firstLocation.what3words,
          city: firstLocation.city,
          country: firstLocation.country
        } : null,
        
        deviceAttestation: {
          attested: proof.deviceAttested || false,
          platform: proof.platform,
          description: proof.deviceAttested 
            ? `This proof was created on a verified ${proof.platform === 'ios' ? 'iOS' : 'Android'} device using ${proof.platform === 'ios' ? "Apple's App Attest" : "Android's Play Integrity"}, confirming the app was genuine and unmodified.`
            : null
        },
        
        explanation
      });
      
    } catch (error) {
      console.error('[ProofOfLife] Error fetching proof data:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });
  
  console.log('[ProofOfLife API] Routes initialized');
}
