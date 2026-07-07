CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2
LDFLAGS  := -lcurl -pthread

# Platform-specific include paths.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  CXXFLAGS += -I/opt/homebrew/include
endif
SRC_DIR  := src
TEST_DIR := tests
OUT_DIR  := build
TARGET   := $(OUT_DIR)/apex-cli

SRCS     := $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/scanners/*.cpp) $(wildcard $(SRC_DIR)/knowledge/*.cpp)
OBJS     := $(patsubst $(SRC_DIR)/%.cpp,$(OUT_DIR)/%.o,$(SRCS))
LIB_OBJS := $(filter-out $(OUT_DIR)/main.o,$(OBJS))
TEST_SRCS := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJS := $(patsubst $(TEST_DIR)/%.cpp,$(OUT_DIR)/test_%.o,$(TEST_SRCS))

.PHONY: all build test clean format lint check run hooks

all: build

build: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OUT_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MMD -c -o $@ $<

test: $(OUT_DIR)/test_runner
	./$(OUT_DIR)/test_runner

$(OUT_DIR)/test_runner: $(TEST_OBJS) $(LIB_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OUT_DIR)/test_%.o: $(TEST_DIR)/%.cpp
	@mkdir -p $(OUT_DIR)
	$(CXX) $(CXXFLAGS) -MMD -c -o $@ $<

run: build
	./$(TARGET)

format:
	clang-format -i $(SRC_DIR)/*.cpp $(SRC_DIR)/*.hpp $(TEST_DIR)/*.cpp 2>/dev/null || true

lint:
	cppcheck --std=c++17 --enable=all --suppress=missingIncludeSystem $(SRC_DIR)/ 2>&1

check: format lint build test

hooks:
	@cp scripts/git/pre-commit.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Git hooks installed."

disclosure: ## Generate disclosure report from scan output
	@bash scripts/disclosure-report.sh $(or $(OUTPUT),.) $(if $(LANG),--lang $(LANG))

find-contact: ## Find responsible disclosure contact for a domain
	@bash scripts/find-disclosure-contact.sh $(DOMAIN)

cvedb-init: ## Initialize local CVE database
	@bash scripts/cvedb-init.sh

cvedb-refresh: ## Fetch latest CVEs from NVD (SOFTWARE= for single product)
	@bash scripts/cvedb-refresh.sh $(if $(SOFTWARE),--software="$(SOFTWARE)")

cvedb-search: ## Search CVE database (Q= for query, SOFTWARE= for product)
	@bash scripts/cvedb-search.sh $(if $(SOFTWARE),--software "$(SOFTWARE)") $(if $(Q),"$(Q)")

cvedb-stats: ## Show CVE database statistics
	@bash scripts/cvedb-search.sh --stats

train-up: ## Start vulnerable training containers (100 use-cases)
	@docker compose -f tests/vulnerability_battery/docker-compose.yml up -d vuln-web vuln-auth vuln-headers vuln-upload vuln-api vuln-infra vuln-ssrf vuln-cicd
	@echo "Targets: localhost:8081-8088"

train-down: ## Stop training containers
	@docker compose -f tests/vulnerability_battery/docker-compose.yml down

ctf-up: ## Start HTB-style CTF challenges (ports 5001-5012)
	@bash scripts/ctf-train.sh --up

ctf-down: ## Stop CTF challenges
	@bash scripts/ctf-train.sh --down

ctf-train: build ## Run apex-cli against CTF challenges and validate findings
	@bash scripts/ctf-train.sh

ctf-validate: ## Validate CTF training results (no scan)
	@bash scripts/ctf-train.sh --validate

train: build ## Run apex-cli against training targets and validate
	@tests/vulnerability_battery/run_tests.sh --quick

train-validate: ## Validate training results (no scan)
	@tests/vulnerability_battery/run_tests.sh --quick

vulhub-setup: ## Clone/update vulhub (328 CVE environments)
	@bash scripts/vulhub.sh setup

vulhub-list: ## List vulhub environments (FILTER= to search)
	@bash scripts/vulhub.sh list $(FILTER)

vulhub-train: ## Train against vulhub CVEs (FILTER= e.g. spring, log4j)
	@bash scripts/vulhub.sh train $(FILTER)

clean:
	rm -rf $(OUT_DIR)

-include $(OUT_DIR)/*.d

bounty: ## Hunt bounties: make bounty PROGRAM=yahoo
	python3 scripts/apex-bounty.py $${PROGRAM:-yahoo}

bounty-scope: ## Hunt with scope file: make bounty-scope FILE=scope.txt
	python3 scripts/apex-bounty.py --scope $${FILE} -j 10

