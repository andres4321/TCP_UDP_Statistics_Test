#include <string>
#include <iostream>
#include <map>
#include <thread>
#include <iomanip>
#include <ctime>
#include <csignal>
#include <chrono>
#include <mutex>
#include <vector>
#include <future>
#include <sstream>

#include <gtest/gtest.h>
#include <gmock/gmock.h> 


#include "Adapter.h"
#include "stdafx.h"



namespace {

	Adapter TestAdapter;

	class cAdapterTest : public testing::Test {
	protected:

		cAdapterTest() {}

		virtual ~cAdapterTest() {}
		virtual void SetUp() {}
		virtual void TearDown() {}
	};

	TEST_F(cAdapterTest, RegisteringLocalAddresses )
	{

		TestAdapter.AddLocalAddress( (unsigned int)0x050AA8C0 );
		TestAdapter.AddLocalAddress((unsigned int)0x0F0AA8C0);
		TestAdapter.AddLocalAddress((unsigned int)0x190AA8C0);
		TestAdapter.AddLocalAddress((unsigned int)0x230AA8C0);
		TestAdapter.AddLocalAddress((unsigned int)0x2D0AA8C0);

		EXPECT_EQ(0x050AA8C0, TestAdapter.LocalAddresses[0]) << "Local address 192.168.10.5 not loaded correctly.";
		EXPECT_EQ(0x0F0AA8C0, TestAdapter.LocalAddresses[1]) << "Local address 192.168.10.15 not loaded correctly.";
		EXPECT_EQ(0x190AA8C0, TestAdapter.LocalAddresses[2]) << "Local address 192.168.10.25 not loaded correctly.";
		EXPECT_EQ(0x230AA8C0, TestAdapter.LocalAddresses[3]) << "Local address 192.168.10.35 not loaded correctly.";
		EXPECT_EQ(0x2D0AA8C0, TestAdapter.LocalAddresses[4]) << "Local address 192.168.10.45 not loaded correctly.";

		EXPECT_EQ(0x060AA8C0, TestAdapter.DetectRemoteAddress( (unsigned int)0x050AA8C0, (unsigned int) 0x060AA8C0 ) );
		EXPECT_EQ(0x060AA8C0, TestAdapter.DetectRemoteAddress((unsigned int)0x060AA8C0, (unsigned int)0x050AA8C0));

		EXPECT_EQ(0x240AA8C0, TestAdapter.DetectRemoteAddress((unsigned int)0x190AA8C0, (unsigned int)0x240AA8C0));
		EXPECT_EQ(0x240AA8C0, TestAdapter.DetectRemoteAddress((unsigned int)0x240AA8C0, (unsigned int)0x190AA8C0));

		EXPECT_EQ(0x2F0AA8C0, TestAdapter.DetectRemoteAddress((unsigned int)0x2D0AA8C0, (unsigned int)0x2F0AA8C0));
		EXPECT_EQ(0x2F0AA8C0, TestAdapter.DetectRemoteAddress((unsigned int)0x2F0AA8C0, (unsigned int)0x2D0AA8C0));
	}


	TEST_F(cAdapterTest, TestingStatisticsRunOnSavedLog )
	{
		std::ostringstream Capture;
		int i;
		const char *pc_pos, *pc_CaptureBaseString;
		std::string s_Capture;

#include "TestFile.h"

		try
		{
			TestAdapter.StartSniffingStatistics();

			for ( i = 0; i < 10; i++ )
			{
				std::cout << "Testing packet counting, pass " << i / 2 + 1 << " ..." << std::endl;
				
				std::this_thread::sleep_for(std::chrono::milliseconds(5000));
				TestAdapter.PrintStatistics(&Capture, TestAdapter.GetAdapterStatistics());

				s_Capture = Capture.str();
				pc_CaptureBaseString = s_Capture.c_str();

				pc_pos = strstr(pc_CaptureBaseString, "82.131.14.128");
				EXPECT_EQ(0, strncmp( (const char*)pc_pos, (const char*)TestStrings[i], strlen((const char*)TestStrings[i])));

				i++;

				pc_pos = strstr(pc_CaptureBaseString, "Total");
				EXPECT_EQ(0, strncmp((const char*)pc_pos, (const char*)TestStrings[i], strlen((const char*)TestStrings[i])));

				Capture.str("");
			}
		}
		catch (std::exception e)
		{
			//std::cout << std::endl << e.what() << std::endl;
			EXPECT_EQ(0, strcmp("Sniffing statistics thread has exited with code -2", e.what()));
		}
	}

}  // namespace


int main( int argc, char** argv )
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
