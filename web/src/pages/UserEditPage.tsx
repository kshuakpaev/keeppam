import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, hasPerm, type Asset, type PamGroup, type Role, type User, type UserSSHKey, type UserVaultSSHKey } from "../api";
import { useAuth } from "../auth";
import { useI18n } from "../i18n";

export function UserEditPage() {
  const { id } = useParams<{ id: string }>();
  const { user: me } = useAuth();
  const { t, te } = useI18n();
  const nav = useNavigate();
  const [target, setTarget] = useState<User | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [pamGroups, setPamGroups] = useState<PamGroup[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [sshKeys, setSshKeys] = useState<UserSSHKey[]>([]);
  const [vaultKeys, setVaultKeys] = useState<UserVaultSSHKey[]>([]);
  const [vaultName, setVaultName] = useState("");
  const [vaultPriv, setVaultPriv] = useState("");
  const [installFor, setInstallFor] = useState("");
  const [sshAssets, setSshAssets] = useState<Asset[]>([]);
  const [installAsset, setInstallAsset] = useState("");
  const [installAccount, setInstallAccount] = useState("");
  const [passkeys, setPasskeys] = useState<{ id: string; name: string; created_at: string }[]>([]);
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [x509Identity, setX509Identity] = useState("");
  const [status, setStatus] = useState("active");
  const [role, setRole] = useState("operator");
  const [tags, setTags] = useState("");
  const [error, setError] = useState("");
  const [msg, setMsg] = useState("");
  const [tempPwd, setTempPwd] = useState("");
  const [loading, setLoading] = useState(true);
  const [keyName, setKeyName] = useState("");
  const [keyPub, setKeyPub] = useState("");

  const canWrite = hasPerm(me, "users.write");
  const canResetMfa = hasPerm(me, "users.reset_mfa");
  const canInstall = canWrite && hasPerm(me, "assets.write");

  async function loadKeys(userId: string) {
    const res = await api.listUserSSHKeys(userId);
    setSshKeys(res.keys || []);
  }

  async function loadVaultKeys(userId: string) {
    const res = await api.listUserVaultSSHKeys(userId);
    setVaultKeys(res.keys || []);
  }

  async function loadPasskeys(userId: string) {
    const res = await api.listUserWebAuthn(userId);
    setPasskeys(res.credentials || []);
  }

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    Promise.all([api.getUser(id), api.listRoles(), api.listGroups(), api.listUserSSHKeys(id), api.listUserWebAuthn(id), api.listUserVaultSSHKeys(id)])
      .then(([u, r, g, keys, wa, vault]) => {
        setTarget(u);
        setEmail(u.email);
        setDisplayName(u.display_name || "");
        setX509Identity(u.x509_identity || "");
        setStatus(u.status);
        setRole((u.roles && u.roles[0]) || "operator");
        setTags((u.tags || []).join(", "));
        setGroupIds(u.group_ids || []);
        setRoles(r.roles || []);
        setPamGroups(g.groups || []);
        setSshKeys(keys.keys || []);
        setVaultKeys(vault.keys || []);
        setPasskeys(wa.credentials || []);
      })
      .catch((err) => setError(te(err, "userEdit.loadError")))
      .finally(() => setLoading(false));
  }, [id, te]);

  async function onSave(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    setMsg("");
    try {
      const updated = await api.updateUser(id, {
        email,
        display_name: displayName,
        status,
        roles: [role],
        group_ids: groupIds,
        x509_identity: x509Identity,
        tags: tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
      });
      setTarget(updated);
      setX509Identity(updated.x509_identity || "");
      setTags((updated.tags || []).join(", "));
      setMsg(t("userEdit.saved"));
    } catch (err) {
      setError(te(err, "userEdit.saveError"));
    }
  }

  async function onResetPassword() {
    if (!id) return;
    setError("");
    try {
      const res = await api.resetPassword(id);
      setTempPwd(res.temporary_password);
      setMsg(t("userEdit.passwordReset"));
      const u = await api.getUser(id);
      setTarget(u);
    } catch (err) {
      setError(te(err, "userEdit.passwordResetError"));
    }
  }

  async function onResetMfa() {
    if (!id) return;
    setError("");
    try {
      await api.resetMfa(id);
      setMsg(t("userEdit.mfaReset"));
      const u = await api.getUser(id);
      setTarget(u);
      await loadPasskeys(id);
    } catch (err) {
      setError(te(err, "userEdit.mfaResetError"));
    }
  }

  async function onAddKey(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    try {
      await api.addUserSSHKey(id, { name: keyName || undefined, public_key: keyPub });
      setKeyName("");
      setKeyPub("");
      setMsg(t("userEdit.sshKeyAdded"));
      await loadKeys(id);
    } catch (err) {
      setError(te(err, "userEdit.sshKeyAddError"));
    }
  }

  async function onDeleteKey(key: UserSSHKey) {
    if (!id || !canWrite) return;
    if (!confirm(t("userEdit.deleteKeyConfirm", { name: key.name }))) return;
    try {
      await api.deleteUserSSHKey(id, key.id);
      setMsg(t("userEdit.sshKeyDeleted"));
      await loadKeys(id);
    } catch (err) {
      setError(te(err, "userEdit.sshKeyDeleteError"));
    }
  }

  async function onAddVault(e: FormEvent) {
    e.preventDefault();
    if (!id || !canWrite) return;
    setError("");
    try {
      await api.addUserVaultSSHKey(id, { name: vaultName || undefined, private_key: vaultPriv });
      setVaultName("");
      setVaultPriv("");
      setMsg(t("userEdit.vaultKeyAdded"));
      await loadVaultKeys(id);
    } catch (err) {
      setError(te(err, "userEdit.vaultKeyAddError"));
    }
  }

  async function onDeleteVault(key: UserVaultSSHKey) {
    if (!id || !canWrite) return;
    if (!confirm(t("userEdit.deleteKeyConfirm", { name: key.name }))) return;
    try {
      await api.deleteUserVaultSSHKey(id, key.id);
      if (installFor === key.id) setInstallFor("");
      setMsg(t("userEdit.vaultKeyDeleted"));
      await loadVaultKeys(id);
    } catch (err) {
      setError(te(err, "userEdit.vaultKeyDeleteError"));
    }
  }

  async function onActivateVault(key: UserVaultSSHKey) {
    if (!id || !canWrite) return;
    setError("");
    try {
      await api.activateUserVaultSSHKey(id, key.id);
      setMsg(t("userEdit.vaultKeyActive"));
      await loadVaultKeys(id);
    } catch (err) {
      setError(te(err, "common.error"));
    }
  }

  async function onOpenInstall(keyId: string) {
    setInstallFor(keyId);
    setInstallAsset("");
    setInstallAccount("");
    if (sshAssets.length > 0 || !hasPerm(me, "assets.read")) return;
    try {
      const res = await api.listAllAssets({ status: "listed" });
      setSshAssets((res.assets || []).filter((a) => a.protocol === "ssh" && a.status === "active"));
    } catch (err) {
      setError(te(err, "userEdit.installError"));
    }
  }

  async function onPickInstallAsset(assetId: string) {
    setInstallAsset(assetId);
    setInstallAccount("");
    if (!assetId) return;
    try {
      const asset = await api.getAsset(assetId);
      const accounts = (asset.accounts || []).filter(
        (acc) => acc.status === "active" && (acc.auth_method === "password" || acc.auth_method === "ssh_key") && acc.has_secret,
      );
      setSshAssets((prev) => prev.map((a) => (a.id === asset.id ? { ...a, accounts } : a)));
    } catch (err) {
      setError(te(err, "userEdit.installError"));
    }
  }

  async function onInstallVault(e: FormEvent) {
    e.preventDefault();
    if (!id || !canInstall || !installFor || !installAsset || !installAccount) return;
    setError("");
    try {
      await api.installUserVaultSSHKey(id, installFor, { asset_id: installAsset, account_id: installAccount });
      setMsg(t("userEdit.installDone"));
      setInstallFor("");
    } catch (err) {
      setError(te(err, "userEdit.installError"));
    }
  }

  if (loading) return <p className="muted">{t("common.loading")}</p>;
  if (!target) {
    return (
      <div>
        <p className="error">{error || t("userEdit.notFound")}</p>
        <Link to="/users">{t("userEdit.backToList")}</Link>
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar">
        <div>
          <p className="muted" style={{ marginBottom: "0.35rem" }}>
            <Link to="/users">{t("nav.users")}</Link> / {target.username}
          </p>
          <h1>{t("userEdit.title")}</h1>
          <p className="muted mono">{target.id}</p>
        </div>
        <button className="btn secondary" type="button" onClick={() => nav("/users")}>
          {t("common.back")}
        </button>
      </div>

      {error && <p className="error">{error}</p>}
      {msg && <p className="ok">{msg}</p>}
      {tempPwd && (
        <p className="ok">
          {t("users.tempPassword")} <span className="mono">{tempPwd}</span>
        </p>
      )}

      <form className="card" onSubmit={onSave} style={{ maxWidth: 520 }}>
        <label>{t("login.username")}</label>
        <input value={target.username} disabled />

        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={!canWrite}
          required
        />

        <label htmlFor="display_name">{t("userEdit.displayName")}</label>
        <input
          id="display_name"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          disabled={!canWrite}
        />

        <label htmlFor="x509_identity">x509 identity (CN / email SAN)</label>
        <input
          id="x509_identity"
          className="mono"
          value={x509Identity}
          onChange={(e) => setX509Identity(e.target.value)}
          disabled={!canWrite}
          placeholder={t("userEdit.x509Placeholder")}
        />
        <p className="muted" style={{ marginTop: 0 }}>
          {t("userEdit.x509Hint")}
        </p>

        <label htmlFor="status">{t("common.status")}</label>
        <select
          id="status"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          disabled={!canWrite}
        >
          <option value="active">active</option>
          <option value="disabled">disabled</option>
          <option value="locked">locked</option>
        </select>

        <label htmlFor="role">{t("users.role")}</label>
        <select
          id="role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          disabled={!canWrite}
        >
          {roles.map((r) => (
            <option key={r.id} value={r.name}>
              {r.name}
            </option>
          ))}
        </select>

        <label>{t("userEdit.pamGroups")}</label>
        <p className="muted" style={{ marginTop: 0 }}>
          {t("userEdit.pamGroupsHint")}
        </p>
        <div style={{ marginBottom: "0.75rem" }}>
          {pamGroups.map((g) => (
            <label key={g.id} className="row" style={{ gap: 8, alignItems: "center", marginBottom: 4 }}>
              <input
                type="checkbox"
                checked={groupIds.includes(g.id)}
                disabled={!canWrite}
                onChange={() =>
                  setGroupIds((ids) => (ids.includes(g.id) ? ids.filter((x) => x !== g.id) : [...ids, g.id]))
                }
              />
              <span className="mono">{g.parent_name ? `${g.parent_name} / ${g.name}` : g.name}</span>
              <span className="muted">{g.description}</span>
            </label>
          ))}
          {pamGroups.length === 0 && <p className="muted">{t("userEdit.noGroups")}</p>}
        </div>

        <label htmlFor="tags">{t("userEdit.abacTags")}</label>
        <input
          id="tags"
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          disabled={!canWrite}
          placeholder="prod/sre, pci"
        />

        <div className="meta-grid">
          <div>
            <span className="muted">MFA</span>
            <div>{target.mfa_enabled ? t("userEdit.mfaEnabled") : t("userEdit.mfaDisabled")}</div>
          </div>
          <div>
            <span className="muted">{t("userEdit.source")}</span>
            <div className="mono">{target.auth_source}</div>
          </div>
          <div>
            <span className="muted">{t("userEdit.lastLogin")}</span>
            <div className="mono">
              {target.last_login_at ? new Date(target.last_login_at).toLocaleString() : "—"}
            </div>
          </div>
          <div>
            <span className="muted">{t("userEdit.passwordChange")}</span>
            <div>
              {target.must_change_password ? t("userEdit.passwordChangeRequired") : t("userEdit.passwordChangeNotRequired")}
            </div>
          </div>
        </div>

        <div className="row" style={{ marginTop: "1rem" }}>
          {canWrite && (
            <button className="btn" type="submit">
              {t("common.save")}
            </button>
          )}
          {canWrite && (
            <button className="btn secondary" type="button" onClick={() => void onResetPassword()}>
              {t("userEdit.resetPassword")}
            </button>
          )}
          {canResetMfa && (
            <button className="btn danger" type="button" onClick={() => void onResetMfa()}>
              {t("userEdit.resetMfa")}
            </button>
          )}
        </div>
      </form>

      <div className="card" style={{ maxWidth: 640, marginTop: "1.25rem" }}>
        <h2>{t("userEdit.passkeysTitle")}</h2>
        <p className="muted">{t("userEdit.passkeysHint")}</p>
        {passkeys.length === 0 ? (
          <p className="muted">{t("userEdit.noKeys")}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("common.name")}</th>
                <th>{t("userEdit.created")}</th>
              </tr>
            </thead>
            <tbody>
              {passkeys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="mono">{new Date(k.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" style={{ maxWidth: 640, marginTop: "1.25rem" }}>
        <h2>{t("userEdit.sshKeysTitle")}</h2>
        <p className="muted">
          {t("userEdit.sshKeysHint", { username: target.username })}
        </p>
        {sshKeys.length === 0 ? (
          <p className="muted">{t("userEdit.noKeys")}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("common.name")}</th>
                <th>{t("userEdit.fingerprint")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sshKeys.map((k) => (
                <tr key={k.id}>
                  <td>{k.name}</td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>
                    {k.fingerprint}
                  </td>
                  <td>
                    {canWrite && (
                      <button className="btn danger" type="button" onClick={() => void onDeleteKey(k)}>
                        {t("common.delete")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {canWrite && (
          <form onSubmit={onAddKey} style={{ marginTop: "1rem" }}>
            <label>{t("common.name")}</label>
            <input
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
              placeholder={t("userEdit.keyNamePlaceholder")}
            />
            <label>{t("userEdit.publicKey")}</label>
            <textarea
              value={keyPub}
              onChange={(e) => setKeyPub(e.target.value)}
              required
              rows={3}
              placeholder="ssh-ed25519 AAAA… comment"
              style={{ width: "100%", fontFamily: "monospace" }}
            />
            <button className="btn" type="submit" style={{ marginTop: "0.5rem" }}>
              {t("userEdit.addKey")}
            </button>
          </form>
        )}
      </div>

      <div className="card" style={{ maxWidth: 640, marginTop: "1.25rem" }}>
        <h2>{t("userEdit.vaultKeysTitle")}</h2>
        <p className="muted">{t("userEdit.vaultKeysHint")}</p>
        {vaultKeys.length === 0 ? (
          <p className="muted">{t("userEdit.noKeys")}</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("common.name")}</th>
                <th>{t("userEdit.fingerprint")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {vaultKeys.map((k) => (
                <tr key={k.id}>
                  <td>
                    {k.name}{" "}
                    {k.active ? <span className="muted">({t("userEdit.vaultKeyActive")})</span> : null}
                    <div className="mono muted" style={{ wordBreak: "break-all", marginTop: "0.25rem" }}>
                      {k.public_key}
                    </div>
                  </td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>
                    {k.fingerprint}
                  </td>
                  <td>
                    {canWrite && !k.active && (
                      <button className="btn" type="button" onClick={() => void onActivateVault(k)}>
                        {t("userEdit.vaultKeyMakeActive")}
                      </button>
                    )}{" "}
                    {canInstall && (
                      <button className="btn" type="button" onClick={() => void onOpenInstall(k.id)}>
                        {t("userEdit.installOnServer")}
                      </button>
                    )}{" "}
                    {canWrite && (
                      <button className="btn danger" type="button" onClick={() => void onDeleteVault(k)}>
                        {t("common.delete")}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {installFor && canInstall && (
          <form onSubmit={onInstallVault} style={{ marginTop: "1rem" }}>
            <p className="muted">{t("userEdit.installHint")}</p>
            <label>{t("common.name")}</label>
            <select value={installAsset} onChange={(e) => void onPickInstallAsset(e.target.value)} required>
              <option value="" />
              {sshAssets.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
            <label>{t("assets.loginOnTarget")}</label>
            <select value={installAccount} onChange={(e) => setInstallAccount(e.target.value)} required>
              <option value="" />
              {(sshAssets.find((a) => a.id === installAsset)?.accounts || []).map((acc) => (
                <option key={acc.id} value={acc.id}>
                  {acc.username}
                </option>
              ))}
            </select>
            <button className="btn" type="submit" style={{ marginTop: "0.5rem" }}>
              {t("userEdit.install")}
            </button>
          </form>
        )}
        {canWrite && (
          <form onSubmit={onAddVault} style={{ marginTop: "1rem" }}>
            <label>{t("common.name")}</label>
            <input
              value={vaultName}
              onChange={(e) => setVaultName(e.target.value)}
              placeholder={t("userEdit.keyNamePlaceholder")}
            />
            <label>{t("userEdit.privateKey")}</label>
            <textarea
              value={vaultPriv}
              onChange={(e) => setVaultPriv(e.target.value)}
              required
              rows={6}
              placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"}
              style={{ width: "100%", fontFamily: "monospace" }}
              autoComplete="off"
            />
            <button className="btn" type="submit" style={{ marginTop: "0.5rem" }}>
              {t("userEdit.addKey")}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
