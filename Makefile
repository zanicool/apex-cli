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

SRCS     := $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/scanners/*.cpp)
OBJS     := $(patsubst $(SRC_DIR)/%.cpp,$(OUT_DIR)/%.o,$(SRCS))
LIB_OBJS := $(filter-out $(OUT_DIR)/main.o,$(OBJS))
TEST_SRCS := $(wildcard $(TEST_DIR)/*.cpp)
TEST_OBJS := $(patsubst $(TEST_DIR)/%.cpp,$(OUT_DIR)/test_%.o,$(TEST_SRCS))

.PHONY: all build test clean format lint check run

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

clean:
	rm -rf $(OUT_DIR)

-include $(OUT_DIR)/*.d
