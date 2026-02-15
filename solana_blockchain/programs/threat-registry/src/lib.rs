// Solana Smart Contract for AI Firewall Threat Registry
// Language: Rust (Anchor Framework)
// Purpose: Store and verify malicious IP addresses on Solana blockchain

use anchor_lang::prelude::*;
use anchor_lang::solana_program::clock::Clock;

declare_id!("FiReWa11ThreatReg1stryPr0gramID11111111111");

#[program]
pub mod ai_firewall_threat_registry {
    use super::*;

    /// Report a new malicious IP address
    pub fn report_threat(
        ctx: Context<ReportThreat>,
        ip_address: String,
        threat_type: String,
        confidence: u8,
        metadata: String,
    ) -> Result<()> {
        let threat = &mut ctx.accounts.threat;
        let reporter = &ctx.accounts.reporter;
        let clock = Clock::get()?;

        require!(confidence <= 100, ErrorCode::InvalidConfidence);
        require!(ip_address.len() <= 45, ErrorCode::IPTooLong); // IPv6 max length
        require!(threat_type.len() <= 50, ErrorCode::ThreatTypeTooLong);
        require!(metadata.len() <= 500, ErrorCode::MetadataTooLong);

        threat.ip_address = ip_address;
        threat.threat_type = threat_type;
        threat.confidence = confidence;
        threat.metadata = metadata;
        threat.reporter = reporter.key();
        threat.timestamp = clock.unix_timestamp;
        threat.report_count = 1;
        threat.status = ThreatStatus::Pending;
        threat.total_confirmations = 0;
        threat.bump = *ctx.bumps.get("threat").unwrap();

        msg!("Threat reported: {} by {}", threat.ip_address, reporter.key());

        Ok(())
    }

    /// Confirm an existing threat report (when multiple users report same IP)
    pub fn confirm_threat(
        ctx: Context<ConfirmThreat>,
        ip_address: String,
    ) -> Result<()> {
        let threat = &mut ctx.accounts.threat;
        let reporter = &ctx.accounts.reporter;
        let clock = Clock::get()?;

        require!(
            threat.ip_address == ip_address,
            ErrorCode::IPMismatch
        );

        // Increment confirmation count
        threat.report_count += 1;
        threat.total_confirmations += 1;
        threat.last_confirmed = clock.unix_timestamp;

        // If 10+ users confirm, mark as CONFIRMED
        if threat.report_count >= 10 && threat.status == ThreatStatus::Pending {
            threat.status = ThreatStatus::Confirmed;
            msg!("Threat CONFIRMED: {} ({} reports)", threat.ip_address, threat.report_count);
            
            // TODO: Reward all reporters with tokens
            // This would integrate with an SPL token program
        }

        msg!("Threat confirmed by {}: {} (total: {})", 
            reporter.key(), threat.ip_address, threat.report_count);

        Ok(())
    }

    /// Mark a threat as false positive
    pub fn mark_false_positive(
        ctx: Context<MarkFalsePositive>,
        ip_address: String,
    ) -> Result<()> {
        let threat = &mut ctx.accounts.threat;
        let authority = &ctx.accounts.authority;

        require!(
            threat.ip_address == ip_address,
            ErrorCode::IPMismatch
        );

        threat.status = ThreatStatus::FalsePositive;
        
        msg!("Threat marked as false positive by {}: {}", 
            authority.key(), threat.ip_address);

        Ok(())
    }

    /// Query threat information
    pub fn get_threat_info(
        ctx: Context<GetThreatInfo>,
        _ip_address: String,
    ) -> Result<ThreatInfo> {
        let threat = &ctx.accounts.threat;

        Ok(ThreatInfo {
            ip_address: threat.ip_address.clone(),
            threat_type: threat.threat_type.clone(),
            confidence: threat.confidence,
            report_count: threat.report_count,
            status: threat.status.clone(),
            first_seen: threat.timestamp,
            last_confirmed: threat.last_confirmed,
            total_confirmations: threat.total_confirmations,
        })
    }

    /// Update threat metadata (for verified reporters only)
    pub fn update_threat_metadata(
        ctx: Context<UpdateThreatMetadata>,
        ip_address: String,
        new_metadata: String,
    ) -> Result<()> {
        let threat = &mut ctx.accounts.threat;

        require!(
            threat.ip_address == ip_address,
            ErrorCode::IPMismatch
        );
        require!(new_metadata.len() <= 500, ErrorCode::MetadataTooLong);

        threat.metadata = new_metadata;

        msg!("Threat metadata updated: {}", threat.ip_address);

        Ok(())
    }
}

// Account Structures

#[derive(Accounts)]
#[instruction(ip_address: String)]
pub struct ReportThreat<'info> {
    #[account(
        init,
        payer = reporter,
        space = 8 + Threat::INIT_SPACE,
        seeds = [b"threat", ip_address.as_bytes()],
        bump
    )]
    pub threat: Account<'info, Threat>,
    
    #[account(mut)]
    pub reporter: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(ip_address: String)]
pub struct ConfirmThreat<'info> {
    #[account(
        mut,
        seeds = [b"threat", ip_address.as_bytes()],
        bump = threat.bump
    )]
    pub threat: Account<'info, Threat>,
    
    pub reporter: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(ip_address: String)]
pub struct MarkFalsePositive<'info> {
    #[account(
        mut,
        seeds = [b"threat", ip_address.as_bytes()],
        bump = threat.bump
    )]
    pub threat: Account<'info, Threat>,
    
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(ip_address: String)]
pub struct GetThreatInfo<'info> {
    #[account(
        seeds = [b"threat", ip_address.as_bytes()],
        bump = threat.bump
    )]
    pub threat: Account<'info, Threat>,
}

#[derive(Accounts)]
#[instruction(ip_address: String)]
pub struct UpdateThreatMetadata<'info> {
    #[account(
        mut,
        seeds = [b"threat", ip_address.as_bytes()],
        bump = threat.bump
    )]
    pub threat: Account<'info, Threat>,
    
    pub authority: Signer<'info>,
}

// Data Structures

#[account]
#[derive(InitSpace)]
pub struct Threat {
    #[max_len(45)]
    pub ip_address: String,           // IPv4 or IPv6
    
    #[max_len(50)]
    pub threat_type: String,          // "Phishing", "Malware", "DDoS", etc.
    
    pub confidence: u8,               // 0-100
    
    #[max_len(500)]
    pub metadata: String,             // JSON metadata
    
    pub reporter: Pubkey,             // First reporter
    pub timestamp: i64,               // Unix timestamp
    pub last_confirmed: i64,          // Last confirmation timestamp
    pub report_count: u32,            // Number of reports
    pub total_confirmations: u32,     // Total confirmations
    pub status: ThreatStatus,         // Pending/Confirmed/FalsePositive
    pub bump: u8,                     // PDA bump seed
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, InitSpace)]
pub enum ThreatStatus {
    Pending,
    Confirmed,
    FalsePositive,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ThreatInfo {
    pub ip_address: String,
    pub threat_type: String,
    pub confidence: u8,
    pub report_count: u32,
    pub status: ThreatStatus,
    pub first_seen: i64,
    pub last_confirmed: i64,
    pub total_confirmations: u32,
}

// Error Codes

#[error_code]
pub enum ErrorCode {
    #[msg("Confidence must be between 0 and 100")]
    InvalidConfidence,
    
    #[msg("IP address too long (max 45 characters)")]
    IPTooLong,
    
    #[msg("Threat type too long (max 50 characters)")]
    ThreatTypeTooLong,
    
    #[msg("Metadata too long (max 500 characters)")]
    MetadataTooLong,
    
    #[msg("IP address mismatch")]
    IPMismatch,
}
