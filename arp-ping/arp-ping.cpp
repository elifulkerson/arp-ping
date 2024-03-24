#include "stdafx.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <iphlpapi.h>
//#include <stdio.h>
//#include <stdlib.h>

#include <iostream>
using namespace std;	

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

int CTRL_C_ABORT;

LARGE_INTEGER cpu_frequency;
LARGE_INTEGER response_timer1;
LARGE_INTEGER response_timer2;

#include <thread>

int THREAD_DIE;  // 0 is default, 1 wait, 2 is reset, 3 is bail

void threaddie(int ms) {
	// after X ms, kill the whole thing.

	if (ms == -1) {
		return;
	}

	// yes, this is highly imprecise.
	for (int i = 0; i < ms; i += 0) {
		Sleep(1);
		// this is the global that indicates we don't need to die anymore, as in, we aren't inside of the SendArp call
		//if (THREAD_DIE > 0) {
		//	cout << " work is over " << endl;
		//	return;
		//}

		//if ( i % 1000 == 0 && i != 0) {
		//	cout << "die: " << i << endl;
		//}

		if (THREAD_DIE == 0) {
			i++;
			//cout << "+";
		}
		if (THREAD_DIE == 1) {
			// noop, we are just going to halt the loop for now so we don't lose the thread
			//cout << ".";
		}
		if (THREAD_DIE == 2) {
			// reset i and continue on
			i = 0;
			THREAD_DIE = 0;
			//cout << "reset";
		}
		if (THREAD_DIE == 3) {
			// we don't need this loop anymore
			//cout << "loopover";
			return;
		}
		if (THREAD_DIE == 4) {
			// positive reset.  We just got a success, so we want to pause the count, but we want to reset i first
			i = 0;
			THREAD_DIE = 1;
			return;
		}
	}
	// different error code for this, why not
	//cout << " time to die " << endl;

	// if we fell this far, its time to die
	cout << "Timeout Abort" << endl;
	exit(3);
}

void controlc() {
	if (CTRL_C_ABORT == 1) {
		cout << "Hard Abort." << endl;
		exit(1);
	}
	cout << "Soft abort.  CTRL-C again for Hard abort." << endl;
	CTRL_C_ABORT = 1;
	//return true;
	
}

void version()
{
		cout << "arp-ping.exe 0.45  September 29 2016" << endl;
		cout << "compiled: " << __DATE__ << " " << __TIME__ << endl;
		cout << endl;
		cout << "arp-ping.exe by Eli Fulkerson " << endl;
		cout << "Please see http://www.elifulkerson.com/projects/ for updates. " << endl;
		cout << endl;
		exit(1);
	
}

void usage()
{
	printf("\n");
	printf("Usage: arp-ping.exe [options] target\n");
	printf("\t-s ip : specify source ip\n");
	printf("\t-n X  : ping X times\n");
	printf("\t-t    : ping until stopped with CTRL-C\n");
	printf("\t-x    : exit immediately after successful ping\n");
	printf("\t-i X  : ping every X seconds\n");
	printf("\t-d    : do an 'arp -d *' between pings (requires Administrator)\n");
	printf("\t        (-d prevents cached ARP responses on Windows XP.)\n");
	printf("\t-c    : include date and time on each line\n");
	printf("\t-m X  : ignore failures that take less than X milliseconds\n");
	printf("\t-.	: print a dot (.) for every ignored failure\n");
	printf("\t-w X  : after ~X milliseconds, if we haven't gotten a response, exit the program\n");
	printf("\t-l    : print debug log\n");
	printf("\t-v    : print version and exit\n");
	printf("\n");

	exit(1);
}

void print_error( DWORD errcode) {
	switch (errcode) {
	case ERROR_BAD_NET_NAME:
		cout << "SendARP returned ERROR_BAD_NET_NAME.\n";
		break;
	case ERROR_BUFFER_OVERFLOW:
		cout << "SendARP returned ERROR_BUFFER_OVERFLOW.\n";
		break;
	case ERROR_GEN_FAILURE:
		cout << "SendARP returned ERROR_GEN_FAILURE.\n";
		break;
	case ERROR_INVALID_PARAMETER:
		cout << "SendARP returned ERROR_INVALID_PARAMETER.\n";
		break;
	case ERROR_INVALID_USER_BUFFER:
		cout << "SendARP returned ERROR_INVALID_USER_BUFFER.\n";
		break;
	case ERROR_NOT_FOUND:
		cout << "SendARP returned ERROR_NOT_FOUND.\n";
		break;
	case ERROR_NOT_SUPPORTED:
		cout << "SendARP returned ERROR_NOT_SUPPORTED.\n";
		break;
	default:
		cout << "SendARP returned other error: " << errcode << ".\n";
		break;
	}

}

u_long LookupAddress(const char* pcHost)
{
	in_addr Address;
    u_long nRemoteAddr = inet_addr(pcHost);
	bool was_a_name = false;

    if (nRemoteAddr == INADDR_NONE) {
        // pcHost isn't a dotted IP, so resolve it through DNS
        hostent* pHE = gethostbyname(pcHost);
		
        if (pHE == 0) {
            return INADDR_NONE;
        }
        nRemoteAddr = *((u_long*)pHE->h_addr_list[0]);
		was_a_name = true;

    }
	if (was_a_name) {
		memcpy(&Address, &nRemoteAddr, sizeof(u_long)); 
		cout << "DNS: " << pcHost << " is " << inet_ntoa(Address) << endl;
	}
    return nRemoteAddr;
}

int __cdecl main(int argc, char **argv)
{
    DWORD dwRetVal;
    IPAddr DestIp = 0;
    IPAddr SrcIp = 0;       /* default for src ip */
    ULONG MacAddr[2];       /* for 6-byte hardware addresses */
    ULONG PhysAddrLen = 6;  /* default to length of six bytes */

    char *DestIpString = NULL;
    char *SrcIpString = NULL;

    BYTE *bPhysAddr;
    unsigned int i;


	int times_to_ping = 4;
	int auto_exit_on_success = 0;
	int ping_interval = 1;
	int clear_arp = 0;
	int show_timestamp = 0;

	int loopcounter = 0;
	double response_time;

	int number_of_pings = 0;	// total number of tcpings issued
	double running_total_ms = 0;	// running total of values of pings... divide by number_of_pings for avg
	double lowest_ping = 50000;		// lowest ping in series ... starts high so it will drop
	double max_ping = 0;			// highest ping in series
	
	int success_counter = 0;
	int failure_counter = 0;
	int deferred_counter = 0;

	int minimum_milliseconds = 0;
	bool verbose = false;
	bool print_dots = false;

	SetConsoleCtrlHandler((PHANDLER_ROUTINE)&controlc, TRUE);
	CTRL_C_ABORT = 0;

	THREAD_DIE = 1;
	int wait_milliseconds = -1;

	// Start Winsock up
    WSAData wsaData;
	int nCode;
    if ((nCode = WSAStartup(MAKEWORD(1, 1), &wsaData)) != 0) {
		cout << "WSAStartup() returned error code " << nCode << "." <<
				endl;
        return 255;
    }

    if (argc > 1) {
        for (i = 1; i < (unsigned int) argc; i++) {
            if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
                switch (tolower(argv[i][1])) {
                /*case 'l':
                    PhysAddrLen = (ULONG) atol(argv[++i]);
                    break;*/
				case '.':
					print_dots = true;
					break;
				case 'm':
					minimum_milliseconds = atoi(argv[++i]);
					break;
				case 'l':
					verbose = true;
					break;
				case 'd':
					clear_arp = 1;
					break;
                case 's':
                    SrcIpString = argv[++i];
                    SrcIp = inet_addr(SrcIpString);
                    break;
				case 'n':
					times_to_ping = atoi(argv[++i]);
					break;
				case 't':
					times_to_ping = -1;
					break;
				case 'x':
					auto_exit_on_success = 1;
					break;
				case 'i':
					ping_interval = atoi(argv[++i]);
					break;
				case 'w':
					wait_milliseconds = atoi(argv[++i]);
					break;
				case 'v':
					version();
					break;
				case 'c':
					show_timestamp = 1;
					break;
                case 'h':
                default:
                    usage();
                    break;
                }               /* end switch */
            } else
                DestIpString = argv[i];
        }                       /* end for */
	} else {
        usage();
	}

	
	if (verbose) {
		cout << "Debug logging is on.  This is developer debugging information more so than network debugging information.  You may look the error codes up at http://msdn.microsoft.com/en-us/library/windows/desktop/aa366358(v=vs.85).aspx if you wish.  Some have several possible interpretations.\n\n";
	}


    if (DestIpString == NULL || DestIpString[0] == '\0')
        usage();

	DestIp = LookupAddress(DestIpString);

	if (DestIp == INADDR_NONE) {
		cout << "Error: could not determine IP address for " << DestIpString << endl;
		return 255;
	}

	// launch our death thread
	if (wait_milliseconds != -1) {
		THREAD_DIE = 2;
	} 
	std::thread suicide_thread(threaddie, wait_milliseconds);
	

	while ( (loopcounter < times_to_ping || times_to_ping == -1 ) && CTRL_C_ABORT == 0) {

		if (clear_arp == 1) {
			system("arp -d * > NUL");
		}

		SetThreadAffinityMask(GetCurrentThread(),1); 
		
		// start the timer right before we do the connection
		bool done = false;
		while (!done) {

			memset(&MacAddr, 0xff, sizeof (MacAddr));
			PhysAddrLen = 6;

			
			QueryPerformanceFrequency((LARGE_INTEGER *)&cpu_frequency);
			QueryPerformanceCounter((LARGE_INTEGER *) &response_timer1);

			dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
			
			QueryPerformanceCounter((LARGE_INTEGER *) &response_timer2);

			// pause the die timer, I don't want to include the sleep-between-attempts 
			THREAD_DIE = 1;

			response_time=( (double) ( (response_timer2.QuadPart - response_timer1.QuadPart) * (double) 1000.0 / (double) cpu_frequency.QuadPart) );

			if ( (dwRetVal != NO_ERROR) && (response_time < minimum_milliseconds)) {
				// we got an error, but it happened faster than our minimum so lets ignore it.
				if (print_dots && !verbose) {
					cout << ".";
				}
				if (verbose) {
					cout << "(Error ignored due to minimum time threshold.)\n";
					print_error(dwRetVal);
				}
			} else {
				done = true;
			}

		}

		

		// Timestamp variablees
		time_t rawtime;
		struct tm * timeinfo;
		char dateStr [11];
		char timeStr [9];
		if (show_timestamp == 1) {
			_strtime( timeStr );
			time ( &rawtime );
			timeinfo = localtime ( &rawtime );
			strftime(dateStr, 11, "%Y:%m:%d",timeinfo);
			cout << dateStr << " " << timeStr << " ";
		}


		if (dwRetVal == NO_ERROR) {
			success_counter++;

			running_total_ms += response_time;

			if (response_time < lowest_ping)
			{
				lowest_ping = response_time;
			}

			if (response_time > max_ping)
			{
				max_ping = response_time;
			}

			cout << "Reply that ";

			bPhysAddr = (BYTE *) & MacAddr;
			if (PhysAddrLen) {
				for (i = 0; i < (int) PhysAddrLen; i++) {
					if (i == (PhysAddrLen - 1))
						printf("%.2X", (int) bPhysAddr[i]);
					else
						printf("%.2X:", (int) bPhysAddr[i]);
				}
			} else {
				cout << "[No MAC Address]";
			}
			cout << " is " << DestIpString << " in ";

	    } else {
			failure_counter++;
			cout << "No response.  ";
			if (verbose) {
					print_error(dwRetVal);
			}
		}


		cout.precision(3);
		cout.setf(ios::showpoint);
		cout.setf(ios::fixed);
		
		cout << response_time << "ms";
		cout << endl;

		number_of_pings++;
		loopcounter++;
		if ((loopcounter == times_to_ping) || ((auto_exit_on_success == 1) && (success_counter > 0))) {
			break;
		}

		int zzz = 0;
		double wakeup = (ping_interval * 1000) - response_time;
		if (wakeup > 0 )
		{
			while (zzz < wakeup && CTRL_C_ABORT ==0) {
				Sleep(10);
				zzz += 10;
			}
		}
		// if we succeeded last time, we reset our die timer.  If we failed we simply re-enable it.
		if (dwRetVal == NO_ERROR) { THREAD_DIE = 2; }
		else { THREAD_DIE = 0; }
	}

	// we're done, so allow the suicide thread to abort
	THREAD_DIE = 3;

cout << endl << "Ping statistics for " << DestIpString << "/arp" << endl;
	cout << "     " << number_of_pings << " probes sent. "<< endl;
	cout << "     " << success_counter << " successful, " << failure_counter << " failed." << endl;

	if (success_counter > 0) {
		if ( failure_counter > 0) {
			cout << "Approximate trip times in milli-seconds (successful connections only):" << endl;
		} else {
			cout << "Approximate trip times in milli-seconds:" << endl;
		}
		cout.precision(3);
		cout << "     Minimum = " << lowest_ping << "ms, Maximum = " << max_ping << "ms, Average = " << running_total_ms/number_of_pings << "ms" <<endl;
	} else {
		cout << "Was unable to connect, cannot provide trip statistics." << endl;
	}
	
    WSACleanup();

	suicide_thread.join();

	// report our total, abject failure.
	if (success_counter == 0) {
		return 1;
	}
	
	// return our intermittent failure
	if (success_counter > 0 && failure_counter > 0) {
		return 2;	
	}

    return 0;
}

