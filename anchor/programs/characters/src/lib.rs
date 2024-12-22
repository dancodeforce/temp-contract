use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount},
};
use mpl_token_metadata::{
    instruction::{create_metadata_accounts_v3, create_master_edition_v3},
    state::DataV2,
};

declare_id!("PROGRAM_ID");

#[program]
pub mod characters {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        name: String,
        symbol: String,
        base_token_uri: String,
        initial_expiry_duration: i64,
        royalty_fee_numerator: u16,
        token_types: Vec<u64>,
        token_prices: Vec<u64>,
        token_enabled_statuses: Vec<bool>,
        payment_mint: Option<Pubkey>,
    ) -> Result<()> {
        require!(royalty_fee_numerator <= 10000, ErrorCode::RoyaltyFeeTooHigh);
        require!(
            token_types.len() == token_prices.len() && token_types.len() == token_enabled_statuses.len(),
            ErrorCode::MismatchedInputLengths
        );

        let state = &mut ctx.accounts.state;
        state.authority = ctx.accounts.authority.key();
        state.name = name;
        state.symbol = symbol;
        state.base_token_uri = base_token_uri;
        state.initial_expiry_duration = initial_expiry_duration;
        state.royalty_fee_numerator = royalty_fee_numerator;
        state.mint_enabled = true;
        state.paused = false;
        state.token_counter = 0;
        state.token_data = Vec::new();
        state.whitelisted_wallets = Vec::new();
        
        state.payment_mint = payment_mint.unwrap();

        // Create treasury PDA
        let (treasury_pda, treasury_bump) = Pubkey::find_program_address(
            &[b"treasury", state.payment_mint.as_ref()],
            ctx.program_id,
        );
        state.treasury = treasury_pda;
        state.treasury_bump = treasury_bump;

        // Initialize token types
        for i in 0..token_types.len() {
            state.token_types.push(TokenTypeInfo {
                token_type: token_types[i],
                price: token_prices[i],
                enabled: token_enabled_statuses[i],
            });
        }

        // Add authority to whitelist
        state.whitelisted_wallets.push(ctx.accounts.authority.key());

        Ok(())
    }

    pub fn mint(
        ctx: Context<MintNFT>,
        token_type: u64,
    ) -> Result<()> {
        let state = &ctx.accounts.state;
        require!(state.mint_enabled, ErrorCode::MintingDisabled);
        require!(!state.paused, ErrorCode::ProgramPaused);
        
        // Verify treasury PDA
        let treasury_seeds = &[
            b"treasury",
            state.payment_mint.as_ref(),
            &[state.treasury_bump],
        ];
        require!(
            ctx.accounts.treasury.key() == state.treasury,
            ErrorCode::InvalidTreasury
        );
        
        let token_type_info = state.token_types
            .iter()
            .find(|tt| tt.token_type == token_type)
            .ok_or(ErrorCode::InvalidTokenType)?;
        require!(token_type_info.enabled, ErrorCode::TokenTypeNotEnabled);

        // Handle payment
        let transfer_accounts = Transfer {
            from: ctx.accounts.payment_account.to_account_info(),
            to: ctx.accounts.treasury.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                transfer_accounts,
            ),
            token_type_info.price,
        )?;
        
        let state = &mut ctx.accounts.state;
        state.token_counter += 1;
        let token_id = state.token_counter;

        // Create metadata
        let name = format!("{} #{}", ctx.accounts.state.name, token_type);
        let uri = format!("{}{}", ctx.accounts.state.base_token_uri, token_type);
        
        let creator = vec![mpl_token_metadata::state::Creator {
            address: ctx.accounts.authority.key(),
            verified: true,
            share: 100,
        }];

        let data_v2 = DataV2 {
            name,
            symbol: ctx.accounts.state.symbol.clone(),
            uri,
            seller_fee_basis_points: ctx.accounts.state.royalty_fee_numerator,
            creators: Some(creator),
            collection: None,
            uses: None,
        };

        // Create metadata account
        let create_metadata_ix = create_metadata_accounts_v3(
            ctx.accounts.token_metadata_program.key(),
            ctx.accounts.metadata.key(),
            ctx.accounts.mint.key(),
            ctx.accounts.authority.key(),
            ctx.accounts.authority.key(),
            ctx.accounts.authority.key(),
            data_v2.name,
            data_v2.symbol,
            data_v2.uri,
            Some(data_v2.creators.unwrap()),
            data_v2.seller_fee_basis_points,
            true,
            true,
            None,
            None,
            None,
        );

        // Create master edition
        let create_master_edition_ix = create_master_edition_v3(
            ctx.accounts.token_metadata_program.key(),
            ctx.accounts.master_edition.key(),
            ctx.accounts.mint.key(),
            ctx.accounts.authority.key(),
            ctx.accounts.authority.key(),
            ctx.accounts.metadata.key(),
            ctx.accounts.authority.key(),
            Some(1), // Max supply of 1 for NFTs
        );

        // Execute instructions
        solana_program::program::invoke(
            &create_metadata_ix,
            &[
                ctx.accounts.metadata.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
                ctx.accounts.rent.to_account_info(),
            ],
        )?;

        solana_program::program::invoke(
            &create_master_edition_ix,
            &[
                ctx.accounts.master_edition.to_account_info(),
                ctx.accounts.metadata.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
                ctx.accounts.rent.to_account_info(),
            ],
        )?;

        state.token_data.push(TokenData {
            token_id,
            token_type,
            expiry: Clock::get()?.unix_timestamp + state.initial_expiry_duration,
            locked: false,
        });

        Ok(())
    }

    pub fn update_base_uri(ctx: Context<AdminOnly>, new_base_uri: String) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.base_token_uri = new_base_uri;
        Ok(())
    }

    pub fn update_royalty(ctx: Context<AdminOnly>, new_royalty_fee_numerator: u16) -> Result<()> {
        require!(new_royalty_fee_numerator <= 10000, ErrorCode::RoyaltyFeeTooHigh);
        let state = &mut ctx.accounts.state;
        state.royalty_fee_numerator = new_royalty_fee_numerator;
        Ok(())
    }

    pub fn set_payment_token(ctx: Context<AdminOnly>, new_payment_mint: Pubkey) -> Result<()> {
        require!(new_payment_mint != Pubkey::default(), ErrorCode::InvalidTokenAddress);
        let state = &mut ctx.accounts.state;
        
        // Create new treasury PDA
        let (new_treasury_pda, new_treasury_bump) = Pubkey::find_program_address(
            &[b"treasury", new_payment_mint.as_ref()],
            ctx.program_id,
        );

        // Update state with new treasury info
        state.payment_mint = new_payment_mint;
        state.treasury = new_treasury_pda;
        state.treasury_bump = new_treasury_bump;

        Ok(())
    }

    pub fn toggle_minting(ctx: Context<AdminOnly>, enabled: bool) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.mint_enabled = enabled;
        Ok(())
    }

    pub fn toggle_pause(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.paused = paused;
        Ok(())
    }

    pub fn add_to_whitelist(ctx: Context<AdminOnly>, wallet: Pubkey) -> Result<()> {
        let state = &mut ctx.accounts.state;
        if !state.whitelisted_wallets.contains(&wallet) {
            state.whitelisted_wallets.push(wallet);
        }
        Ok(())
    }

    pub fn remove_from_whitelist(ctx: Context<AdminOnly>, wallet: Pubkey) -> Result<()> {
        let state = &mut ctx.accounts.state;
        if let Some(pos) = state.whitelisted_wallets.iter().position(|&w| w == wallet) {
            state.whitelisted_wallets.remove(pos);
        }
        Ok(())
    }

    pub fn lock_token(ctx: Context<AdminOnly>, token_id: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        if let Some(token) = state.token_data.iter_mut().find(|t| t.token_id == token_id) {
            token.locked = true;
        }
        Ok(())
    }

    pub fn unlock_token(ctx: Context<AdminOnly>, token_id: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        if let Some(token) = state.token_data.iter_mut().find(|t| t.token_id == token_id) {
            token.locked = false;
        }
        Ok(())
    }

    pub fn burn(ctx: Context<BurnNFT>, token_id: u64) -> Result<()> {
        let state = &ctx.accounts.state;
        require!(
            state.whitelisted_wallets.contains(&ctx.accounts.authority.key()),
            ErrorCode::NotWhitelisted
        );
        require!(!state.paused, ErrorCode::ProgramPaused);

        // Verify token exists and is not locked
        let token = state.token_data
            .iter()
            .find(|t| t.token_id == token_id)
            .ok_or(ErrorCode::TokenNotFound)?;
        require!(!token.locked, ErrorCode::TokenLocked);

        // Burn the token
        let cpi_accounts = token::Burn {
            mint: ctx.accounts.mint.to_account_info(),
            from: ctx.accounts.token_account.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        token::burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                cpi_accounts,
            ),
            1,
        )?;

        // Remove token data
        let state = &mut ctx.accounts.state;
        if let Some(pos) = state.token_data.iter().position(|t| t.token_id == token_id) {
            state.token_data.remove(pos);
        }

        Ok(())
    }

    pub fn multi_burn(ctx: Context<MultiBurnNFT>, token_ids: Vec<u64>) -> Result<()> {
        let state = &ctx.accounts.state;
        require!(
            state.whitelisted_wallets.contains(&ctx.accounts.authority.key()),
            ErrorCode::NotWhitelisted
        );
        require!(!state.paused, ErrorCode::ProgramPaused);
        require!(
            token_ids.len() == ctx.accounts.mints.len() && 
            token_ids.len() == ctx.accounts.token_accounts.len(),
            ErrorCode::MismatchedAccountsLength
        );

        // Verify and burn each token
        for (i, &token_id) in token_ids.iter().enumerate() {
            // Verify token exists and is not locked
            let token = state.token_data
                .iter()
                .find(|t| t.token_id == token_id)
                .ok_or(ErrorCode::TokenNotFound)?;
            require!(!token.locked, ErrorCode::TokenLocked);

            // Burn the token
            let cpi_accounts = token::Burn {
                mint: ctx.accounts.mints[i].to_account_info(),
                from: ctx.accounts.token_accounts[i].to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            };
            token::burn(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    cpi_accounts,
                ),
                1,
            )?;

            // Remove token data
            let state = &mut ctx.accounts.state;
            if let Some(pos) = state.token_data.iter().position(|t| t.token_id == token_id) {
                state.token_data.remove(pos);
            }
        }

        Ok(())
    }

    pub fn multi_mint(
        ctx: Context<MultiMintNFT>,
        amounts: Vec<u64>,
        token_types: Vec<u64>,
        receivers: Vec<Pubkey>,
    ) -> Result<()> {
        let state = &ctx.accounts.state;
        require!(
            state.whitelisted_wallets.contains(&ctx.accounts.authority.key()),
            ErrorCode::NotWhitelisted
        );
        require!(!state.paused, ErrorCode::ProgramPaused);
        require!(amounts.len() > 0, ErrorCode::EmptyAmountsArray);
        require!(
            amounts.len() == token_types.len() && amounts.len() == receivers.len(),
            ErrorCode::MismatchedInputLengths
        );

        let mut total_mints = 0;
        for amount in amounts.iter() {
            total_mints += amount;
        }
        require!(
            ctx.accounts.mints.len() == total_mints as usize && 
            ctx.accounts.metadatas.len() == total_mints as usize &&
            ctx.accounts.token_accounts.len() == total_mints as usize,
            ErrorCode::MismatchedAccountsLength
        );

        let mut mint_index = 0;
        for i in 0..amounts.len() {
            let amount = amounts[i];
            let token_type = token_types[i];
            let receiver = receivers[i];

            let token_type_info = state.token_types
                .iter()
                .find(|tt| tt.token_type == token_type)
                .ok_or(ErrorCode::InvalidTokenType)?;
            require!(token_type_info.enabled, ErrorCode::TokenTypeNotEnabled);

            let state = &mut ctx.accounts.state;
            for _ in 0..amount {
                state.token_counter += 1;
                let token_id = state.token_counter;

                // Create metadata
                let name = format!("{} #{}", ctx.accounts.state.name, token_type);
                let uri = format!("{}{}", ctx.accounts.state.base_token_uri, token_type);
                
                let creator = vec![mpl_token_metadata::state::Creator {
                    address: ctx.accounts.authority.key(),
                    verified: true,
                    share: 100,
                }];

                let data_v2 = DataV2 {
                    name,
                    symbol: ctx.accounts.state.symbol.clone(),
                    uri,
                    seller_fee_basis_points: ctx.accounts.state.royalty_fee_numerator,
                    creators: Some(creator),
                    collection: None,
                    uses: None,
                };

                // Create metadata account
                let create_metadata_ix = create_metadata_accounts_v3(
                    ctx.accounts.token_metadata_program.key(),
                    ctx.accounts.metadatas[mint_index].key(),
                    ctx.accounts.mints[mint_index].key(),
                    ctx.accounts.authority.key(),
                    ctx.accounts.authority.key(),
                    ctx.accounts.authority.key(),
                    data_v2.name,
                    data_v2.symbol,
                    data_v2.uri,
                    Some(data_v2.creators.unwrap()),
                    data_v2.seller_fee_basis_points,
                    true,
                    true,
                    None,
                    None,
                    None,
                );

                // Create master edition
                let create_master_edition_ix = create_master_edition_v3(
                    ctx.accounts.token_metadata_program.key(),
                    ctx.accounts.master_editions[mint_index].key(),
                    ctx.accounts.mints[mint_index].key(),
                    ctx.accounts.authority.key(),
                    ctx.accounts.authority.key(),
                    ctx.accounts.metadatas[mint_index].key(),
                    ctx.accounts.authority.key(),
                    Some(1), // Max supply of 1 for NFTs
                );

                // Execute instructions
                solana_program::program::invoke(
                    &create_metadata_ix,
                    &[
                        ctx.accounts.metadatas[mint_index].to_account_info(),
                        ctx.accounts.mints[mint_index].to_account_info(),
                        ctx.accounts.authority.to_account_info(),
                        ctx.accounts.authority.to_account_info(),
                        ctx.accounts.authority.to_account_info(),
                        ctx.accounts.system_program.to_account_info(),
                        ctx.accounts.rent.to_account_info(),
                    ],
                )?;

                solana_program::program::invoke(
                    &create_master_edition_ix,
                    &[
                        ctx.accounts.master_editions[mint_index].to_account_info(),
                        ctx.accounts.metadatas[mint_index].to_account_info(),
                        ctx.accounts.mints[mint_index].to_account_info(),
                        ctx.accounts.authority.to_account_info(),
                        ctx.accounts.authority.to_account_info(),
                        ctx.accounts.authority.to_account_info(),
                        ctx.accounts.system_program.to_account_info(),
                        ctx.accounts.rent.to_account_info(),
                    ],
                )?;

                // Mint token to receiver
                let cpi_accounts = token::MintTo {
                    mint: ctx.accounts.mints[mint_index].to_account_info(),
                    to: ctx.accounts.token_accounts[mint_index].to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                };
                token::mint_to(
                    CpiContext::new(
                        ctx.accounts.token_program.to_account_info(),
                        cpi_accounts,
                    ),
                    1,
                )?;

                state.token_data.push(TokenData {
                    token_id,
                    token_type,
                    expiry: Clock::get()?.unix_timestamp + state.initial_expiry_duration,
                    locked: false,
                });

                mint_index += 1;
            }
        }

        Ok(())
    }

    pub fn get_token_expiry(ctx: Context<ViewOnly>, token_id: u64) -> Result<Option<i64>> {
        let state = &ctx.accounts.state;
        Ok(state.token_data
            .iter()
            .find(|t| t.token_id == token_id)
            .map(|t| t.expiry))
    }

    pub fn is_whitelisted_wallet(ctx: Context<ViewOnly>, wallet: Pubkey) -> Result<bool> {
        let state = &ctx.accounts.state;
        Ok(state.whitelisted_wallets.contains(&wallet))
    }

    pub fn get_token_details_paginated(
        ctx: Context<ViewTokens>,
        start_index: u64,
        page_size: u64,
    ) -> Result<TokenDetailsPage> {
        let state = &ctx.accounts.state;
        let total_tokens = state.token_data.len() as u64;
        let end_index = std::cmp::min(start_index + page_size, total_tokens);

        let mut page = TokenDetailsPage {
            token_ids: Vec::new(),
            token_types: Vec::new(),
            locked: Vec::new(),
            expiries: Vec::new(),
        };

        for token in state.token_data.iter().skip(start_index as usize).take(page_size as usize) {
            page.token_ids.push(token.token_id);
            page.token_types.push(token.token_type);
            page.locked.push(token.locked);
            page.expiries.push(token.expiry);
        }

        Ok(page)
    }

    pub fn get_all_token_details(
        ctx: Context<ViewTokens>,
    ) -> Result<TokenDetailsPage> {
        let state = &ctx.accounts.state;
        let mut details = TokenDetailsPage {
            token_ids: Vec::new(),
            token_types: Vec::new(),
            locked: Vec::new(),
            expiries: Vec::new(),
        };

        for token in state.token_data.iter() {
            details.token_ids.push(token.token_id);
            details.token_types.push(token.token_type);
            details.locked.push(token.locked);
            details.expiries.push(token.expiry);
        }

        Ok(details)
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + State::INIT_SPACE
    )]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(token_type: u64)]
pub struct MintNFT<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    /// CHECK: Metadata account
    #[account(mut)]
    pub metadata: UncheckedAccount<'info>,
    /// CHECK: Edition account
    #[account(mut)]
    pub master_edition: UncheckedAccount<'info>,
    /// CHECK: Token metadata program
    pub token_metadata_program: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    #[account(mut)]
    /// CHECK: Treasury
    pub treasury: UncheckedAccount<'info>,
    #[account(mut)]
    pub payment_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub payment_mint: Account<'info, Mint>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"treasury", state.payment_mint.as_ref()],
        bump = state.treasury_bump,
    )]
    pub treasury: Account<'info, TokenAccount>,
    #[account(mut)]
    pub receiver: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ViewOnly<'info> {
    pub state: Account<'info, State>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(mut, has_one = authority)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct BurnNFT<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(mut)]
    pub token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct MultiMintNFT<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    /// CHECK: Created by token program
    pub mints: Vec<AccountInfo<'info>>,
    /// CHECK: Created by token metadata program
    pub metadatas: Vec<AccountInfo<'info>>,
    pub master_editions: Vec<AccountInfo<'info>>,
    pub token_accounts: Vec<Account<'info, TokenAccount>>,
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    /// CHECK: Metadata program ID
    #[account(address = mpl_token_metadata::ID)]
    pub token_metadata_program: AccountInfo<'info>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct MultiBurnNFT<'info> {
    #[account(mut)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub mints: Vec<Account<'info, Mint>>,
    pub token_accounts: Vec<Account<'info, TokenAccount>>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ViewTokens<'info> {
    pub state: Account<'info, State>,
}

#[derive(Accounts)]
pub struct SetPaymentToken<'info> {
    #[account(mut, has_one = authority)]
    pub state: Account<'info, State>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub old_treasury: Account<'info, TokenAccount>,
    #[account(mut)]
    pub new_treasury: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
#[derive(Default)]
pub struct State {
    pub authority: Pubkey,
    pub name: String,
    pub symbol: String,
    pub base_token_uri: String,
    pub initial_expiry_duration: i64,
    pub royalty_fee_numerator: u16,
    pub mint_enabled: bool,
    pub paused: bool,
    pub token_counter: u64,
    pub whitelisted_wallets: Vec<Pubkey>,
    pub token_data: Vec<TokenData>,
    pub token_types: Vec<TokenTypeInfo>,
    pub payment_mint: Pubkey,
    pub treasury: Pubkey,
    pub treasury_bump: u8,
}

impl State {
    pub const INIT_SPACE: usize = 
        32 + // authority
        32 + // name
        32 + // symbol
        128 + // base_token_uri
        8 + // initial_expiry_duration
        2 + // royalty_fee_numerator
        1 + // mint_enabled
        1 + // paused
        8 + // token_counter
        32 + // payment_mint
        32 + // treasury
        1 + // treasury_bump
        1024; // Dynamic space for vectors (will reallocate if needed)
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct TokenData {
    pub token_id: u64,
    pub token_type: u64,
    pub expiry: i64,
    pub locked: bool,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TokenTypeInfo {
    pub token_type: u64,
    pub price: u64,
    pub enabled: bool,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct TokenDetailsPage {
    pub token_ids: Vec<u64>,
    pub token_types: Vec<u64>,
    pub locked: Vec<bool>,
    pub expiries: Vec<i64>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Royalty fee cannot be more than 100%")]
    RoyaltyFeeTooHigh,
    #[msg("Minting is disabled")]
    MintingDisabled,
    #[msg("Program is paused")]
    ProgramPaused,
    #[msg("Invalid token type")]
    InvalidTokenType,
    #[msg("Token type not enabled")]
    TokenTypeNotEnabled,
    #[msg("Not whitelisted")]
    NotWhitelisted,
    #[msg("Empty amounts array")]
    EmptyAmountsArray,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Mismatched input lengths")]
    MismatchedInputLengths,
    #[msg("Invalid token address")]
    InvalidTokenAddress,
    #[msg("Invalid treasury account")]
    InvalidTreasury,
    #[msg("Unauthorized access")]
    UnauthorizedAccess,
    #[msg("Mismatched number of accounts")]
    MismatchedAccountsLength,
    #[msg("Numeric overflow")]
    NumericOverflow,
    #[msg("Token not found")]
    TokenNotFound,
    #[msg("Token is locked")]
    TokenLocked,
}
