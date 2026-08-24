import type { LicenseStatus } from "./api";

export function isUnlicensedLicense(lic: LicenseStatus) {
  const s = (lic.source || "").trim();
  return s === "default" || s.startsWith("missing:") || lic.customer === "unlicensed";
}

export function licenseStatusText(
  lic: LicenseStatus,
  t: (key: string, vars?: Record<string, string | number>) => string,
): string {
  const count = lic.asset_count;
  const max = lic.max_assets;
  const unlicensed = isUnlicensedLicense(lic);
  if (lic.expired) {
    return lic.hard_blocked
      ? t("license.expiredBlocked", { count, max })
      : t("license.expiredSoft", { count, max });
  }
  if (unlicensed) {
    return lic.hard_blocked
      ? t("license.unlicensedBlocked", { count, max })
      : t("license.unlicensedSoft", { count, max });
  }
  if (lic.hard_blocked) return t("license.limitBlocked", { count, max });
  if (lic.soft_warn) return t("license.limitWarn", { count, max });
  return "";
}
