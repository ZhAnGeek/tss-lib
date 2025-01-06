# Usage for new process

1. In snarkVM, build inputs
2. In tss-lib, run signing protocol
3. In snarkVM, fill request from output of tss-lib

# Usage for old process

1. In snarkVM, call Request::get_record_h(...). It returns h.
2. In tss-lib, given input h from step 1, run aleo/signing protocol. It returns tvk, sk_tag, g_r, h_r and gamma.
3. In snarkVM, given inputs from step 2, call Request::compute_challenge_and_partial_request(...). It returns challenge.
4. In tss-lib, given input challenge from step 3, run aleo/postsigning protocol. It returns response.
5. In snarkVM, given response from step 4, run Request::fill_signature_and_finalize(...) to finish to request.
