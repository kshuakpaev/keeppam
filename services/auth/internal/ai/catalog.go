package ai

import "strings"

const (
	GroupMock       = "mock"
	GroupOllama     = "ollama"
	GroupGroq       = "groq"
	GroupOpenRouter = "openrouter"

	KindChat  = "chat"
	KindEmbed = "embed"

	PresetCustom = ""
	PresetMock   = "mock"

	DefaultOllamaEndpoint     = "http://ai-runtime:11434"
	DefaultGroqEndpoint       = "https://api.groq.com/openai"
	DefaultOpenRouterEndpoint = "https://openrouter.ai/api"
	DefaultEmbedOllama        = "nomic-embed-text"
)

// ModelPreset is a free-weight or free-tier model the admin can pick in Config.
type ModelPreset struct {
	ID           string `json:"id"`
	Group        string `json:"group"`
	Kind         string `json:"kind"`
	Label        string `json:"label"`
	Model        string `json:"model"`
	EmbedModel   string `json:"embed_model"`
	Endpoint     string `json:"endpoint"`
	Mode         string `json:"mode"`
	NeedsKey     bool   `json:"needs_key"`
	Pull         bool   `json:"pull"`
	CPUFriendly  bool   `json:"cpu_friendly"`
	Notes        string `json:"notes"`
}

type RuntimeModel struct {
	ID      string `json:"id"`
	Source  string `json:"source,omitempty"`
	Installed bool `json:"installed"`
}

type ModelCatalog struct {
	Presets      []ModelPreset  `json:"presets"`
	Runtime      []RuntimeModel `json:"runtime"`
	Preset       string         `json:"preset"`
	RuntimeError string         `json:"runtime_error,omitempty"`
}

func Catalog(allowExternal bool) []ModelPreset {
	all := []ModelPreset{
		{
			ID: PresetMock, Group: GroupMock, Kind: KindChat, Label: "Mock (built-in)",
			Model: "mock", EmbedModel: "mock", Endpoint: "mock://local", Mode: ModeOn,
			Notes: "No GPU, no outbound. Deterministic summaries for CI and air-gap.",
		},
		{
			ID: "ollama-llama32", Group: GroupOllama, Kind: KindChat, Label: "Llama 3.2 3B",
			Model: "llama3.2", EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true, CPUFriendly: true,
			Notes: "Meta Llama 3.2, Apache-style community weights via Ollama. Fits CPU.",
		},
		{
			ID: "ollama-phi3", Group: GroupOllama, Kind: KindChat, Label: "Phi-3 Mini",
			Model: "phi3", EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true, CPUFriendly: true,
			Notes: "Microsoft Phi-3 Mini 3.8B. Light on-prem chat.",
		},
		{
			ID: "ollama-qwen25", Group: GroupOllama, Kind: KindChat, Label: "Qwen 2.5 7B",
			Model: "qwen2.5", EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true, CPUFriendly: true,
			Notes: "Alibaba Qwen 2.5 7B. Strong RU/EN among 7B-class.",
		},
		{
			ID: "ollama-mistral", Group: GroupOllama, Kind: KindChat, Label: "Mistral 7B",
			Model: "mistral", EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true, CPUFriendly: true,
			Notes: "Mistral 7B Instruct. Apache 2.0 weights.",
		},
		{
			ID: "ollama-llama31", Group: GroupOllama, Kind: KindChat, Label: "Llama 3.1 8B",
			Model: "llama3.1", EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true,
			Notes: "Meta Llama 3.1 8B. Needs ~8 GiB RAM Q4.",
		},
		{
			ID: "ollama-gemma2", Group: GroupOllama, Kind: KindChat, Label: "Gemma 2 9B",
			Model: "gemma2", EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true,
			Notes: "Google Gemma 2 9B. Open weights, Gemma license.",
		},
		{
			ID: "ollama-nomic", Group: GroupOllama, Kind: KindEmbed, Label: "nomic-embed-text",
			Model: DefaultEmbedOllama, EmbedModel: DefaultEmbedOllama, Endpoint: DefaultOllamaEndpoint, Mode: ModeOn,
			Pull: true, CPUFriendly: true,
			Notes: "Free embedding model for semantic search (P2). Hash fallback if missing.",
		},
		{
			ID: "groq-llama33", Group: GroupGroq, Kind: KindChat, Label: "Groq Llama 3.3 70B",
			Model: "llama-3.3-70b-versatile", EmbedModel: "mock", Endpoint: DefaultGroqEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "Free Groq tier. OpenAI-compatible. Requires API key; session data leaves the site.",
		},
		{
			ID: "groq-llama31-8b", Group: GroupGroq, Kind: KindChat, Label: "Groq Llama 3.1 8B Instant",
			Model: "llama-3.1-8b-instant", EmbedModel: "mock", Endpoint: DefaultGroqEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "Free Groq tier, low latency.",
		},
		{
			ID: "groq-gemma2", Group: GroupGroq, Kind: KindChat, Label: "Groq Gemma 2 9B",
			Model: "gemma2-9b-it", EmbedModel: "mock", Endpoint: DefaultGroqEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "Free Groq tier, Gemma 2 instruct.",
		},
		{
			ID: "groq-mixtral", Group: GroupGroq, Kind: KindChat, Label: "Groq Mixtral 8x7B",
			Model: "mixtral-8x7b-32768", EmbedModel: "mock", Endpoint: DefaultGroqEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "Free Groq tier, Mixtral instruct.",
		},
		{
			ID: "openrouter-llama32", Group: GroupOpenRouter, Kind: KindChat, Label: "OpenRouter Llama 3.2 3B free",
			Model: "meta-llama/llama-3.2-3b-instruct:free", EmbedModel: "mock", Endpoint: DefaultOpenRouterEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "OpenRouter :free. Requires key; not for air-gap.",
		},
		{
			ID: "openrouter-qwen", Group: GroupOpenRouter, Kind: KindChat, Label: "OpenRouter Qwen 2.5 7B free",
			Model: "qwen/qwen-2.5-7b-instruct:free", EmbedModel: "mock", Endpoint: DefaultOpenRouterEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "OpenRouter :free. Better RU than tiny Llama.",
		},
		{
			ID: "openrouter-gemma2", Group: GroupOpenRouter, Kind: KindChat, Label: "OpenRouter Gemma 2 9B free",
			Model: "google/gemma-2-9b-it:free", EmbedModel: "mock", Endpoint: DefaultOpenRouterEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "OpenRouter :free.",
		},
		{
			ID: "openrouter-mistral", Group: GroupOpenRouter, Kind: KindChat, Label: "OpenRouter Mistral 7B free",
			Model: "mistralai/mistral-7b-instruct:free", EmbedModel: "mock", Endpoint: DefaultOpenRouterEndpoint, Mode: ModeExternal,
			NeedsKey: true,
			Notes: "OpenRouter :free, Apache 2.0 lineage.",
		},
	}
	if allowExternal {
		return all
	}
	out := make([]ModelPreset, 0, len(all))
	for _, p := range all {
		if p.NeedsKey || p.Mode == ModeExternal {
			continue
		}
		out = append(out, p)
	}
	return out
}

func FindPreset(id string) *ModelPreset {
	id = strings.TrimSpace(id)
	if id == "" || id == "__custom__" {
		return nil
	}
	for _, p := range Catalog(true) {
		if p.ID == id {
			cp := p
			return &cp
		}
	}
	return nil
}

func MatchPreset(endpoint, model, embed string, allowExternal bool) string {
	model = strings.TrimSpace(model)
	embed = strings.TrimSpace(embed)
	ep := strings.TrimRight(strings.ToLower(strings.TrimSpace(endpoint)), "/")
	for _, p := range Catalog(allowExternal) {
		if p.Kind == KindEmbed {
			continue
		}
		if !strings.EqualFold(model, p.Model) {
			continue
		}
		pep := strings.TrimRight(strings.ToLower(p.Endpoint), "/")
		switch p.Group {
		case GroupMock:
			if isMockEndpoint(endpoint) || strings.EqualFold(model, "mock") {
				return p.ID
			}
		case GroupOllama:
			if strings.Contains(ep, "11434") || strings.Contains(ep, "ai-runtime") || ep == pep {
				return p.ID
			}
		default:
			if ep == pep {
				return p.ID
			}
		}
	}
	_ = embed
	return PresetCustom
}

func MatchEmbedPreset(endpoint, embed string, allowExternal bool) string {
	embed = strings.TrimSpace(embed)
	if embed == "" || strings.EqualFold(embed, "mock") {
		return PresetMock
	}
	ep := strings.TrimRight(strings.ToLower(strings.TrimSpace(endpoint)), "/")
	for _, p := range Catalog(allowExternal) {
		if p.Kind != KindEmbed {
			continue
		}
		if !strings.EqualFold(embed, p.Model) && !strings.EqualFold(embed, p.EmbedModel) {
			continue
		}
		pep := strings.TrimRight(strings.ToLower(p.Endpoint), "/")
		if strings.Contains(ep, "11434") || strings.Contains(ep, "ai-runtime") || ep == pep || isMockEndpoint(endpoint) {
			return p.ID
		}
	}
	return PresetCustom
}

func runtimeNameMatches(have, want string) bool {
	have = strings.TrimSpace(have)
	want = strings.TrimSpace(want)
	if have == "" || want == "" {
		return false
	}
	if strings.EqualFold(have, want) {
		return true
	}
	// ollama tags: llama3.2:latest
	h, _, _ := strings.Cut(have, ":")
	w, _, _ := strings.Cut(want, ":")
	return strings.EqualFold(h, w)
}
