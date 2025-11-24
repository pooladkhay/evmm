```
# install
qemu-img create -f qcow2 fedora-dev.qcow2 50G

qemu-system-x86_64 \                         
  -machine accel=kvm \
  -m 4096 \
  -smp 4 \
  -cpu host \
  -drive file=fedora-dev.qcow2,if=virtio \
  -cdrom /path/to/fedora.iso \    
  -boot d \                           
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -vga virtio \
  -display sdl,show-cursor=on

# run
qemu-system-x86_64 \
  -machine accel=kvm \
  -m 4096 \
  -smp 4 \
  -cpu host \
  -drive file=/path/to/fedora-dev.qcow2,if=virtio \
  -netdev user,id=net0,hostfwd=tcp::2222-:22 \
  -device virtio-net-pci,netdev=net0 \
  -virtfs local,path=/path/to/be/shared,mount_tag=shared,security_model=passthrough,id=shared \
  -display none \
  -monitor unix:fedora-vm.sock,server,nowait \
  -daemonize

# Graceful shutdown (ACPI powerdown)
echo "system_powerdown" | socat - unix-connect:fedora-vm.sock

# Hard reset
echo "system_reset" | socat - unix-connect:fedora-vm.sock

# Pause VM
echo "stop" | socat - unix-connect:fedora-vm.sock

# Resume VM
echo "cont" | socat - unix-connect:fedora-vm.sock

# Quit QEMU immediately
echo "quit" | socat - unix-connect:fedora-vm.sock
```
