CUR_DIR=$(shell pwd)
BIN_DIR=$(CUR_DIR)/bin
MRTE_COLLECTOR_BIN=$(BIN_DIR)/MRTECollector

ifeq ($(WITH_RACE), )
WITH_RACE=0
endif

ifeq ($(WITH_RACE), 0)
RACE_FLAGS=
else
RACE_FLAGS= -race
endif

GOBUILD_FLAGS += $(RACE_FLAGS)

all: build_player build_collector

help:
	@echo "---- USAGE -----------------------------"
	@echo "[flags] make [targets] [flags]"
	@echo "  targets:"
	@echo "    - clean:	         clean binary and classs files"
	@echo "    - build_player:    build MRTEPlayer"
	@echo "    - build_collector: build MRTECollector"
	@echo "    - run_player:      run MRTEPlayer"
	@echo "    - run_collector:   run MRTECollector"
	@echo "    - help:            show this help messages"
	@echo "  flags:"
	@echo "    - WITH_RACE=[0|1]: 1: go build with '-race' (default:0)"


build_player:
	@echo "======= build player ========"
	#@cat ./MRTEPlayer/build.sh
	sh ./MRTEPlayer/build.sh
	@echo ""

build_collector:
	@echo "======= build collector ========"
	go build $(GOBUILD_FLAGS) -o $(MRTE_COLLECTOR_BIN) MRTECollector/MRTECollector.go 
	@echo ""

run_player:
	@echo "======= run player ========"
	@cat ./MRTEPlayer/run.sh
	sh $(BIN_DIR)/run_player.sh 
	@echo ""

run_collector:
	@echo "======= run collector =============="
	@echo "===================================="
	@echo " NOTICE: require SUDO privileges!!!"
	@echo "===================================="
	sh $(BIN_DIR)/run_collector.sh 
	@echo ""

clean:
	@echo "======= clean ========"
	go clean -cache
	@-rm $(MRTE_COLLECTOR_BIN) 2> /dev/null
	@-rm ./MRTEPlayer/build/* 2> /dev/null
	@echo ""
