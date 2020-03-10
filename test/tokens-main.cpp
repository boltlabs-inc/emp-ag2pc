#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
using namespace std;
using namespace emp;


//const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);
void test(int party, NetIO* io, string name, string check_output = "") {
    // read in the circuit from the location where it was generated
	string file = "/Users/Gijs/projects/libzkchannels/deps/emp-sh2pc/" + name; //TODO: fix path
        cout << file << endl;
	CircuitFile cf(file.c_str());
    //
    // initialize some timing stuff?
	auto t1 = clock_start();
	C2PC twopc(io, party, &cf);
	io->flush();
	cout << "one time:\t"<<party<<"\t" <<time_from(t1)<<endl;

    // preprocessing?
	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "inde:\t"<<party<<"\t"<<time_from(t1)<<endl;

    // more preprocessing?
	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "dep:\t"<<party<<"\t"<<time_from(t1)<<endl;

    // create and fill in input vectors (to all zeros with memset)
    int in_length = party==BOB?cf.n2:cf.n1;
	bool *in = new bool[in_length];
	cout << "input size: max " << cf.n1 << "\t" << cf.n2;
	bool * out = new bool[cf.n3];
	if (party == BOB) {
	    memset(in, false, in_length);
	    uint32_t in1 = 1;
	    int32_to_bool(in, in1, 32);
	} else {
	    uint32_t in2 = 2;
	    int32_to_bool(in, in2, 32);
	    uint32_t in3 = 5;
	    int32_to_bool(&in[32], in3, 32);
	}
	memset(out, false, cf.n3);

	string res = "";
	for(int i = 0; i < 64; ++i)
        res += (in[i]?"1":"0");
    cout << "in: " << res << endl;

    // online protocol execution
	t1 = clock_start();
	twopc.online(in, out);
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;

    // compare result to our hardcoded expected result
	if(party == BOB and check_output.size() > 0){
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << "result: " << res << endl;
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}
	delete[] in;
	delete[] out;
}

int main(int argc, char** argv) {
    // set up parties
	cout << "start1" <<endl;
	int party, port;
	parse_party_and_port(argv, &party, &port);
    NetIO* io = new NetIO(party==BOB ? nullptr:IP, port);
	cout << "start3" <<endl;
	io->set_nodelay();
	cout << "start4" <<endl;
	test(party, io, "test.circuit.txt", string("c000"));
	delete io;
	return 0;
}