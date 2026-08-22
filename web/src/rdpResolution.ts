export type RdpResolution = {
  id: string;
  label: string;
  width: number;
  height: number;
};

export const RDP_RESOLUTIONS: RdpResolution[] = [
  { id: "1024x768", label: "1024 × 768", width: 1024, height: 768 },
  { id: "1280x800", label: "1280 × 800", width: 1280, height: 800 },
  { id: "1280x1024", label: "1280 × 1024", width: 1280, height: 1024 },
  { id: "1366x768", label: "1366 × 768", width: 1366, height: 768 },
  { id: "1600x900", label: "1600 × 900", width: 1600, height: 900 },
  { id: "1920x1080", label: "1920 × 1080", width: 1920, height: 1080 },
  { id: "2560x1440", label: "2560 × 1440", width: 2560, height: 1440 },
  { id: "auto", label: "По размеру окна", width: 0, height: 0 },
];

export const RDP_RES_STORAGE = "kp_rdp_resolution";

const DEFAULT_ID = "1280x800";

export function rdpResolutionById(id: string): RdpResolution {
  return RDP_RESOLUTIONS.find((r) => r.id === id) || RDP_RESOLUTIONS.find((r) => r.id === DEFAULT_ID)!;
}

export function loadRdpResolutionId(): string {
  try {
    const raw = localStorage.getItem(RDP_RES_STORAGE);
    if (raw && RDP_RESOLUTIONS.some((r) => r.id === raw)) return raw;
  } catch {
    /* ignore */
  }
  return DEFAULT_ID;
}

export function saveRdpResolutionId(id: string) {
  try {
    localStorage.setItem(RDP_RES_STORAGE, id);
  } catch {
    /* ignore */
  }
}

export function loadRdpResolution(): RdpResolution {
  return rdpResolutionById(loadRdpResolutionId());
}

export function autoRdpSize(): { width: number; height: number } {
  return {
    width: Math.max(1024, Math.floor(window.innerWidth - 64)),
    height: Math.max(768, Math.floor(window.innerHeight - 160)),
  };
}

export function resolveRdpSize(stored: RdpResolution): { width: number; height: number } {
  if (stored.width > 0 && stored.height > 0) {
    return { width: stored.width, height: stored.height };
  }
  return autoRdpSize();
}
