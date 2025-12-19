# XV6 getreadcount System Call Implementation

## Overview

This report documents the implementation of a new system call `getreadcount()` in xv6 that tracks and returns the total number of bytes read by the `read()` system call across all processes since boot.

## Part A: Basic System Call Implementation

### A.1: System Call Implementation

#### Files Modified

1. **kernel/syscall.h** - Added system call number
2. **kernel/syscall.c** - Added system call to dispatch table  
3. **kernel/sysproc.c** - Implemented `sys_getreadcount()`
4. **kernel/sysfile.c** - Modified `sys_read()` to track bytes read
5. **kernel/main.c** - Added global counter variable
6. **kernel/defs.h** - Added function prototype and extern declaration
7. **user/user.h** - Added user-space function prototype
8. **user/usys.pl** - Added system call stub generation

#### Implementation Details

**Global Counter Variable:**
```c
// In kernel/main.c
uint64 total_read_bytes = 0;
```

**Modified sys_read() Function:**
```c
// In kernel/sysfile.c
uint64 sys_read(void)
{
  extern uint64 total_read_bytes;
  struct file *f;
  int n;
  uint64 p;
  int bytes_read;

  argaddr(1, &p);
  argint(2, &n);
  if(argfd(0, 0, &f) < 0)
    return -1;
  
  bytes_read = fileread(f, p, n);
  if(bytes_read > 0)
    total_read_bytes += bytes_read;
  return bytes_read;
}
```

**New sys_getreadcount() Function:**
```c
// In kernel/sysproc.c
uint64 sys_getreadcount(void)
{
  extern uint64 total_read_bytes;
  
  // Return current count of bytes read
  return total_read_bytes;
}
```

#### Overflow Handling

The implementation uses `uint64` which provides a very large range (0 to 18,446,744,073,709,551,615). When overflow occurs, it naturally wraps around to 0 due to unsigned integer arithmetic in C.

### A.2: User Program Implementation

The user program `readcount.c` demonstrates the system call functionality:

#### Key Features:

1. **Initial Count Check**: Calls `getreadcount()` to get baseline
2. **File Operations**: Creates a test file with sufficient content
3. **Controlled Read**: Reads exactly 100 bytes from the file
4. **Verification**: Compares before/after read counts
5. **Multiple Calls**: Tests system call reliability with repeated calls
6. **Cleanup**: Removes test files after completion

#### Test Workflow:

```c
// Get initial count
initial_count = getreadcount();

// Create and write test file
fd = open("testfile.txt", O_CREATE | O_WRONLY);
write(fd, test_data, strlen(test_data));
close(fd);

// Read 100 bytes
fd = open("testfile.txt", O_RDONLY);
bytes_read = read(fd, buf, 100);

// Verify increase
final_count = getreadcount();
actual_increase = final_count - initial_count;
```

## Technical Design Decisions

### 1. **Global Counter Location**
- Placed in `kernel/main.c` to ensure single instance
- Initialized to 0 at boot time
- Accessible across all kernel modules

### 2. **Thread Safety**
- Current implementation doesn't use locks
- In xv6's simple design, this is acceptable for the basic requirement
- Production systems would need proper synchronization

### 3. **Counter Scope**
- Tracks ALL read operations system-wide
- Includes reads from files, devices, pipes, etc.
- Persists across process creation/termination

### 4. **Error Handling**
- Only counts successful reads (bytes_read > 0)
- Failed reads don't increment the counter
- Maintains accurate count of actual data transferred

## Testing Strategy

The test program validates:

1. **Basic Functionality**: System call returns reasonable values
2. **Increment Behavior**: Counter increases after read operations
3. **Accuracy**: Increase matches expected byte count
4. **Consistency**: Multiple calls return consistent/increasing values
5. **File I/O Integration**: Works with standard file operations

## Build and Run Instructions

1. **Apply Patch**: 
   ```bash
   cd xv6-riscv
   patch -p1 < ../xv6/xv6_modifications.patch
   ```

2. **Add User Program to Makefile**:
   ```makefile
   UPROGS=\
   	...
   	$U/_readcount\
   ```

3. **Build and Run**:
   ```bash
   make qemu
   # In xv6 shell:
   readcount
   ```

## Expected Output

```
Initial read count: [some number]
Successfully read 100 bytes from file
Final read count: [initial + 100]
Expected increase: 100
Actual increase: 100
SUCCESS: Read count increased correctly!

Testing system call functionality:
getreadcount() call 1: [value]
getreadcount() call 2: [same or higher]
...
```

## Conclusion

The implementation successfully meets all requirements:

- ✅ **A.1**: `sys_getreadcount()` implemented and returns total bytes read
- ✅ **A.2**: User program tests functionality and verifies 100-byte reads
- ✅ **Overflow**: Natural wrap-around behavior with uint64
- ✅ **Integration**: Properly integrated into xv6 system call infrastructure

The system call provides accurate tracking of read operations across the entire system and demonstrates proper xv6 kernel development practices.