# goloom-server build helpers.
#
# Targets:
#   make ui            - regenerate templ Go files + recompile Tailwind CSS
#   make ui-watch      - watch mode (templ generate --watch + tailwind --watch)
#   make tools         - download templ CLI and standalone Tailwind CLI binary
#   make build         - build the wg-server binary
#   make clean         - drop build outputs and generated UI files
#
# We intentionally avoid Node — Tailwind ships a single static binary
# we vendor under tools/tailwindcss(.exe). The Makefile detects the host
# OS and downloads the matching release on first run.

GO            ?= go
GOPATH        ?= $(shell $(GO) env GOPATH)
TEMPL         ?= $(GOPATH)/bin/templ
TEMPL_VERSION ?= v0.3.1001

TAILWIND_VERSION ?= v3.4.17

UI_DIR        := internal/admin/ui
TAILWIND_SRC  := $(UI_DIR)/tailwind.src.css
TAILWIND_OUT  := internal/admin/static/tailwind.css
TAILWIND_CFG  := $(UI_DIR)/tailwind.config.js

# --- OS detection (windows / linux / mac) -----------------------------------
ifeq ($(OS),Windows_NT)
  HOST_OS  := windows
  EXE_EXT  := .exe
  TAILWIND_BIN_NAME := tailwindcss-windows-x64.exe
else
  UNAME_S := $(shell uname -s)
  UNAME_M := $(shell uname -m)
  ifeq ($(UNAME_S),Linux)
    HOST_OS := linux
    ifeq ($(UNAME_M),aarch64)
      TAILWIND_BIN_NAME := tailwindcss-linux-arm64
    else
      TAILWIND_BIN_NAME := tailwindcss-linux-x64
    endif
  endif
  ifeq ($(UNAME_S),Darwin)
    HOST_OS := mac
    ifeq ($(UNAME_M),arm64)
      TAILWIND_BIN_NAME := tailwindcss-macos-arm64
    else
      TAILWIND_BIN_NAME := tailwindcss-macos-x64
    endif
  endif
  EXE_EXT :=
endif

TAILWIND_BIN  := tools/tailwindcss$(EXE_EXT)
TAILWIND_URL  := https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/$(TAILWIND_BIN_NAME)

.PHONY: ui ui-watch tools tools-templ tools-tailwind build run clean

ui: tools-templ tools-tailwind
	@echo ">> templ generate"
	$(TEMPL) generate
	@echo ">> tailwindcss build → $(TAILWIND_OUT)"
	$(TAILWIND_BIN) -i $(TAILWIND_SRC) -o $(TAILWIND_OUT) -c $(TAILWIND_CFG) --minify

ui-watch: tools-templ tools-tailwind
	@echo ">> watch mode (templ + tailwind in parallel)"
	$(TEMPL) generate --watch &\
	$(TAILWIND_BIN) -i $(TAILWIND_SRC) -o $(TAILWIND_OUT) -c $(TAILWIND_CFG) --watch

tools: tools-templ tools-tailwind

tools-templ:
	@if [ ! -x "$(TEMPL)" ] && [ ! -f "$(TEMPL).exe" ]; then \
		echo ">> installing templ CLI ($(TEMPL_VERSION))"; \
		$(GO) install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION); \
	fi

tools-tailwind: $(TAILWIND_BIN)

$(TAILWIND_BIN):
	@mkdir -p tools
	@echo ">> downloading $(TAILWIND_BIN_NAME) → $(TAILWIND_BIN)"
	@curl --fail -sSL -o $(TAILWIND_BIN) $(TAILWIND_URL)
	@chmod +x $(TAILWIND_BIN) 2>/dev/null || true

build: ui
	$(GO) build ./cmd/goloom-wg-server

run: build
	./goloom-wg-server$(EXE_EXT)

clean:
	rm -f goloom-wg-server$(EXE_EXT) goloom-wg-client$(EXE_EXT)
	rm -f $(TAILWIND_OUT)
	rm -f $(UI_DIR)/**/*_templ.go $(UI_DIR)/*_templ.go
