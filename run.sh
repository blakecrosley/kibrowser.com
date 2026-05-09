#!/bin/bash

# Ki Browser Website — Development Server Manager
# Usage: ./run.sh {start|stop|restart|status|logs}

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
PID_FILE="$PROJECT_DIR/.server.pid"
LOG_FILE="$PROJECT_DIR/.server.log"
PORT=8300

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        echo -e "${YELLOW}Creating virtual environment...${NC}"
        python3 -m venv "$VENV_DIR"
        source "$VENV_DIR/bin/activate"
        pip install --upgrade pip
        pip install -r "$PROJECT_DIR/requirements.txt"
        echo -e "${GREEN}Virtual environment created!${NC}"
    else
        source "$VENV_DIR/bin/activate"
    fi
}

start_server() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}Server is already running (PID: $PID)${NC}"
            return
        fi
    fi

    setup_venv
    echo -e "${GREEN}Starting development server on port $PORT...${NC}"
    cd "$PROJECT_DIR"
    nohup uvicorn app.main:app --host 0.0.0.0 --port $PORT --reload > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 2

    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${GREEN}Server started! PID: $PID${NC}"
            echo -e "${GREEN}Open http://localhost:$PORT${NC}"
        else
            echo -e "${RED}Failed to start server. Check logs with: ./run.sh logs${NC}"
        fi
    fi
}

stop_server() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${YELLOW}Stopping server (PID: $PID)...${NC}"
            kill $PID
            rm -f "$PID_FILE"
            echo -e "${GREEN}Server stopped.${NC}"
        else
            echo -e "${YELLOW}Server was not running.${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${YELLOW}No PID file found. Server may not be running.${NC}"
    fi
}

status_server() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo -e "${GREEN}Server is running (PID: $PID) on port $PORT${NC}"
        else
            echo -e "${RED}Server is not running (stale PID file)${NC}"
            rm -f "$PID_FILE"
        fi
    else
        echo -e "${RED}Server is not running.${NC}"
    fi
}

show_logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo -e "${YELLOW}No log file found.${NC}"
    fi
}

case "$1" in
    start)
        start_server
        ;;
    stop)
        stop_server
        ;;
    restart)
        stop_server
        sleep 1
        start_server
        ;;
    status)
        status_server
        ;;
    logs)
        show_logs
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
