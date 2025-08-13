pragma circom 2.0.0;

include "../circuits/constants/mds_matrix.json";
include "../circuits/constants/round_constants.json";

template Sbox() {
    signal input in;
    signal output out;
    
    signal s2;
    signal s4;
    signal s5;
    
    s2 <== in * in;
    s4 <== s2 * s2;
    s5 <== s4 * in;
    
    out <== s5;
}

template AddConstant(c) {
    signal input in;
    signal output out;
    out <== in + c;
}

template MDSTimes(t) {
    signal input in[t];
    signal input vec[t];
    signal output out;
    
    signal products[t];
    
    for (var i = 0; i < t; i++) {
        products[i] <== in[i] * vec[i];
    }
    
    out <== products[0];
    for (var i = 1; i < t; i++) {
        out <== out + products[i];
    }
}

template PartialRound(t, roundIdx) {
    signal input in[t];
    signal output out[t];
    
    component addRC[t];
    for (var i = 0; i < t; i++) {
        addRC[i] = AddConstant(round_constants[roundIdx*t + i]);
        addRC[i].in <== in[i];
    }
    
    component sbox = Sbox();
    sbox.in <== addRC[0].out;
    
    signal sboxOut[t];
    sboxOut[0] <== sbox.out;
    for (var i = 1; i < t; i++) {
        sboxOut[i] <== addRC[i].out;
    }
    
    component mdsMult[t];
    for (var i = 0; i < t; i++) {
        mdsMult[i] = MDSTimes(t);
        for (var j = 0; j < t; j++) {
            mdsMult[i].in[j] <== mds_matrix[i][j];
            mdsMult[i].vec[j] <== sboxOut[j];
        }
        out[i] <== mdsMult[i].out;
    }
}

template FullRound(t, roundIdx) {
    signal input in[t];
    signal output out[t];
    
    component addRC[t];
    for (var i = 0; i < t; i++) {
        addRC[i] = AddConstant(round_constants[roundIdx*t + i]);
        addRC[i].in <== in[i];
    }
    
    component sbox[t];
    signal sboxOut[t];
    for (var i = 0; i < t; i++) {
        sbox[i] = Sbox();
        sbox[i].in <== addRC[i].out;
        sboxOut[i] <== sbox[i].out;
    }
    
    component mdsMult[t];
    for (var i = 0; i < t; i++) {
        mdsMult[i] = MDSTimes(t);
        for (var j = 0; j < t; j++) {
            mdsMult[i].in[j] <== mds_matrix[i][j];
            mdsMult[i].vec[j] <== sboxOut[j];
        }
        out[i] <== mdsMult[i].out;
    }
}

template Poseidon2_3_5() {
    signal input in[3];
    signal output out;
    
    var t = 3;
    var nRoundsF = 8;
    var nRoundsP = 57;
    var roundIdx = 0;
    
    signal state[t];
    for (var i = 0; i < t; i++) {
        state[i] <== in[i];
    }
    
    // First full rounds
    for (var r = 0; r < nRoundsF / 2; r++) {
        component round = FullRound(t, roundIdx);
        for (var i = 0; i < t; i++) {
            round.in[i] <== state[i];
            state[i] <== round.out[i];
        }
        roundIdx++;
    }
    
    // Partial rounds
    for (var r = 0; r < nRoundsP; r++) {
        component round = PartialRound(t, roundIdx);
        for (var i = 0; i < t; i++) {
            round.in[i] <== state[i];
            state[i] <== round.out[i];
        }
        roundIdx++;
    }
    
    // Final full rounds
    for (var r = 0; r < nRoundsF / 2; r++) {
        component round = FullRound(t, roundIdx);
        for (var i = 0; i < t; i++) {
            round.in[i] <== state[i];
            state[i] <== round.out[i];
        }
        roundIdx++;
    }
    
    out <== state[0];
}

component main = Poseidon2_3_5();
