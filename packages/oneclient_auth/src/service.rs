use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use oneclient_events::EventBus;
use oneclient_net::RequestClient;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::data::MinecraftAccount;
use crate::error::{AuthError, AuthResult};
use crate::store::{self, CredentialsStore};

pub struct AuthService {
	store: Mutex<CredentialsStore>,
	/// Serialises token renewal per account Microsoft rotates the refresh token
	/// on every use so concurrent renewals would sign the account out
	refresh_guards: StdMutex<HashMap<Uuid, Arc<Mutex<()>>>>,
	net: RequestClient,
	events: EventBus,
}

impl AuthService {
	/// A missing or unreadable `auth.json` yields an empty store rather than
	/// failing so a corrupt file means "sign in again" not "will not start"
	pub async fn load(net: RequestClient, events: EventBus) -> AuthResult<Self> {
		Ok(Self::with_store(CredentialsStore::load().await?, net, events))
	}

	#[must_use]
	pub fn with_store(store: CredentialsStore, net: RequestClient, events: EventBus) -> Self {
		Self {
			store: Mutex::new(store),
			refresh_guards: StdMutex::new(HashMap::new()),
			net,
			events,
		}
	}

	#[tracing::instrument(skip(self), fields(username = %username))]
	pub async fn add_offline_account(&self, username: String) -> AuthResult<MinecraftAccount> {
		self.store
			.lock()
			.await
			.add_offline_account_and_save(username)
			.await
	}

	pub async fn list_accounts(&self) -> Vec<MinecraftAccount> {
		self.store.lock().await.list_accounts()
	}

	pub async fn get_account(&self, id: Uuid) -> Option<MinecraftAccount> {
		self.store.lock().await.get_account(id).cloned()
	}

	#[tracing::instrument(level = "debug", skip_all)]
	pub async fn default_account(&self) -> AuthResult<Option<MinecraftAccount>> {
		self.store.lock().await.default_account().await
	}

	#[tracing::instrument(level = "debug", skip(self), fields(?id))]
	pub async fn set_default_account(&self, id: Option<Uuid>) -> AuthResult<()> {
		self.store.lock().await.set_default_user(id).await
	}

	#[tracing::instrument(skip(self), fields(%id))]
	pub async fn remove_account(&self, id: Uuid) -> AuthResult<()> {
		self.store.lock().await.remove_account(id).await?;
		Ok(())
	}

	pub async fn has_microsoft_account(&self) -> bool {
		self.store.lock().await.has_microsoft_account()
	}

	fn refresh_guard(&self, id: Uuid) -> Arc<Mutex<()>> {
		Arc::clone(
			self.refresh_guards
				.lock()
				.expect("refresh guard registry poisoned")
				.entry(id)
				.or_default(),
		)
	}

	async fn account_snapshot(&self, id: Uuid) -> AuthResult<MinecraftAccount> {
		self.store
			.lock()
			.await
			.get_account(id)
			.cloned()
			.ok_or(AuthError::AccountNotFound(id))
	}

	/// The store lock is never held across the Microsoft handshake only around
	/// the reads and the final write
	#[tracing::instrument(level = "debug", skip(self), fields(%id))]
	async fn renew_token(&self, id: Uuid, force: bool) -> AuthResult<MinecraftAccount> {
		let existing = self.account_snapshot(id).await?;
		if !existing.is_microsoft() || (!force && !existing.is_expired()) {
			return Ok(existing);
		}

		let guard = self.refresh_guard(id);
		let _serialised = guard.lock().await;

		// Re-read under the guard whoever held it may have just refreshed
		let existing = self.account_snapshot(id).await?;
		if !existing.is_microsoft() || (!force && !existing.is_expired()) {
			return Ok(existing);
		}

		tracing::info!(username = %existing.username, "renewing Microsoft access token");
		match crate::msa::refresh_microsoft_account(self.net.http(), &existing).await {
			Ok(refreshed) => {
				self.store
					.lock()
					.await
					.commit_refreshed_account(refreshed.clone())
					.await?;
				Ok(refreshed)
			}
			Err(err) => {
				let err = AuthError::from(err);
				if store::is_transient_auth_error(&err) {
					tracing::warn!("keeping existing token after transient renewal failure: {err}");
					Ok(existing)
				} else {
					Err(err)
				}
			}
		}
	}

	#[tracing::instrument(level = "debug", skip(self), fields(%id))]
	pub async fn refresh_account(&self, id: Uuid) -> AuthResult<MinecraftAccount> {
		self.renew_token(id, true).await
	}

	#[tracing::instrument(level = "debug", skip_all)]
	pub async fn refresh_all_accounts(&self) -> AuthResult<Vec<MinecraftAccount>> {
		let ids: Vec<Uuid> = self.store.lock().await.users.keys().copied().collect();
		let mut refreshed = Vec::with_capacity(ids.len());

		for id in ids {
			refreshed.push(self.renew_token(id, true).await?);
		}

		Ok(refreshed)
	}

	#[tracing::instrument(level = "debug", skip(self), fields(%id))]
	pub async fn account_for_launch(&self, id: Uuid) -> AuthResult<MinecraftAccount> {
		let account = self.renew_token(id, false).await?;

        Ok(account)
	}

	#[tracing::instrument(level = "debug", skip_all)]
	pub async fn default_account_for_launch(&self) -> AuthResult<Option<MinecraftAccount>> {
		let Some(id) = self.store.lock().await.resolve_default_id().await? else {
			return Ok(None);
		};
		Ok(Some(self.account_for_launch(id).await?))
	}
}
