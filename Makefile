CUR_DIR=$(shell pwd)
BIN_DIR=$(CUR_DIR)/bin
MRTE_COLLECTOR_BIN=$(BIN_DIR)/MRTECollector

all: build_player build_collector

help:
	@echo "---- USAGE -----------------------------"
	@echo "make [targets]"
	@echo "  targets:"
	@echo "   - clean:	         clean binary and classs files"
	@echo "   - build_player:    build MRTEPlayer"
	@echo "   - build_collector: build MRTECollector"
	@echo "   - run_player:      run MRTEPlayer"
	@echo "   - run_collector:   run MRTECollector"
	@echo "   - help: show this help messages"


build_player:
	@echo "======= build player ========"
	#@cat ./MRTEPlayer/build.sh
	sh ./MRTEPlayer/build.sh
	@echo ""

build_collector:
	@echo "======= build collector ========"
	go build -o $(MRTE_COLLECTOR_BIN) MRTECollector/MRTECollector.go 
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
