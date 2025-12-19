#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
    int fd;
    char buf[100];
    int initial_count, final_count;
    int bytes_read;
    
    // Get initial read count
    initial_count = getreadcount();
    printf("Initial read count: %d\n", initial_count);
    
    // Create a test file with some content
    fd = open("testfile.txt", 0x200); // O_CREATE | O_WRONLY
    if(fd < 0) {
        printf("Failed to create test file\n");
        exit(1);
    }
    
    // Write some test data (more than 100 bytes)
    char *test_data = "This is a test file for the getreadcount system call. "
                      "We need to write enough data so that we can read 100 bytes from it. "
                      "This should be sufficient content for our test purposes.\n";
    
    write(fd, test_data, strlen(test_data));
    close(fd);
    
    // Now open the file for reading
    fd = open("testfile.txt", 0); // O_RDONLY
    if(fd < 0) {
        printf("Failed to open test file for reading\n");
        exit(1);
    }
    
    // Read exactly 100 bytes from the file
    bytes_read = read(fd, buf, 100);
    if(bytes_read < 0) {
        printf("Failed to read from file\n");
        close(fd);
        exit(1);
    }
    
    printf("Successfully read %d bytes from file\n", bytes_read);
    
    // Get final read count
    final_count = getreadcount();
    printf("Final read count: %d\n", final_count);
    
    // Verify the increase
    int expected_increase = (bytes_read > 100) ? 100 : bytes_read;
    int actual_increase = final_count - initial_count;
    
    printf("Expected increase: %d\n", expected_increase);
    printf("Actual increase: %d\n", actual_increase);
    
    if(actual_increase >= expected_increase) {
        printf("SUCCESS: Read count increased correctly!\n");
    } else {
        printf("ERROR: Read count did not increase as expected\n");
    }
    
    // Clean up
    close(fd);
    unlink("testfile.txt");
    
    // Test overflow behavior by calling getreadcount multiple times
    printf("\nTesting system call functionality:\n");
    for(int i = 0; i < 5; i++) {
        printf("getreadcount() call %d: %d\n", i+1, getreadcount());
    }
    
    exit(0);
}