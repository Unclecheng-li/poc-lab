<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            system($this->cmd);
        }
    }
}
session_start();
echo "OK\n";
