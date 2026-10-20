# Fixed baseline configuration message for TP-Link's HTTP control socket.
# Derived from msg_recv/msg_send and http_init_configByMsg in the supplied
# WR841N firmware: 520 bytes, type 0x7ee, UTF-8, local HTTP enabled on port 80.
# Authentication configuration and request handlers are not changed.
.set noreorder
.text
.globl _start
_start:
    addiu $sp, $sp, -32
    li $v0, 4183
    li $a0, 1
    li $a1, 1
    move $a2, $zero
    syscall
    bne $a3, $zero, failed
    nop
    move $s0, $v0
    li $v0, 4180
    move $a0, $s0
    la $a1, message
    li $a2, 520
    move $a3, $zero
    la $t0, address
    sw $t0, 16($sp)
    li $t0, 13
    sw $t0, 20($sp)
    syscall
    bne $a3, $zero, failed
    nop
    li $v0, 4004
    li $a0, 1
    la $a1, success
    li $a2, 28
    syscall
    move $a0, $zero
    b done
    nop
failed:
    li $a0, 1
done:
    li $v0, 4001
    syscall
.data
.align 2
address:
    .half 1
    .asciz "/var/tmp/8"
.align 2
message:
    .word 0x7ee
    .word 0
    .half 0
    .asciz "utf-8"
    .byte 1, 0
    .half 80
    .space 500
success:
    .ascii "FIRMXPLORE_HTTP_CONFIG_SENT\n"
