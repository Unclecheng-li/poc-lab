<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            file_put_contents("/tmp/rce_proof.txt", shell_exec($this->cmd), FILE_APPEND);
        }
    }
}
session_start();
echo "OK\n";
