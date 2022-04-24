<!-- https://katex.org/docs/supported.html -->

## Keygen

### Round 1.

On input $(keygen,\ i,\ ssid)$ from $\mathcal{P}_i$:

- Sample $u_i \gets \mathbb{F}_q$ and create Sharemir's shares $[\ [\mathrm{Vs}_i], [\mathrm{Sh}_i]\ ] \gets Shamir(u_i)$
- Generate first message $[A_i, \alpha_i] \gets \mathcal{M}(com, \Pi^{sch})$
- Sample two $4\kappa$-bit long preparam safe primes $(p_i, q_i)$ and set $N_i=p_iq_i$
- Sample $r \gets \mathbb{Z}_{N_i}^*, \lambda \gets \mathbb{Z}_{\Phi(N_i)}$ and set $t_i=r^2~ mod~N_i, s_i=t_i^{\lambda}~mod~N_i$
    - Compute Ring-Pedersen params proof $\hat{\psi}_i = \mathcal{M}(prove, \Pi^{prm}, (ssid, i), (N_i, s_i, t_i; \lambda))$
- (TODO) Sample first messages for $\mathrm{Vs}$ $[AA_i, \alpha\alpha_i]\gets\mathcal{M}(com, \Pi^{sch})$
- Sample round id $rid_i \gets \{0, 1\}^\kappa$
- Sample hash commit randomness $cr_i \gets \{0, 1\}^\kappa$
- Compute hash $V_i = \mathcal{H}(ssid, i, \mathrm{Vs}_i, A_i, N_i, s_i, t_i, \hat{\psi}_i, rid_i, cr_i)$

Broadcast $(ssid, i, V_i)$

### Round 2.

Wait until gets $(ssid, j, V_j)$ from all $\mathcal{P}_j$, broadcast public values that are committed $(ssid, i, \mathrm{Vs}_i, A_i, N_i, s_i, t_i, \hat{\psi}_i, rid_i, cr_i)$

### Round 3.

Upon receiving $(ssid_j, j, \mathrm{Vs}_j, A_j, N_j, s_j, t_j, \hat{\psi}_j, rid_j, cr_j)$ from $\mathcal{P}_j$

- Verify $ssid=ssid_j$
- Verify $N_j \ge 2^{8\kappa}$
- Verify $\mathcal{M}(verify, \hat{\psi}_j, \Pi^{prm}, (ssid, j), (N_j, s_j, t_j)) = true$

- Verify $V_j = \mathcal{H}(ssid, j, \mathrm{Vs}_j, A_j, N_j, s_j, t_j, \hat{\psi}_j, rid_j, cr_j)$

When obtaining the above from all $\mathcal{P}_j$

- Set $rid=\oplus_j rid_j$
- Compute $\psi_i=\mathcal{M}(prove, \Pi^{mod}, (ssid, \rho, i), N_i; (p_i, q_i))$
- Compute $\phi_{j,i}=\mathcal{M}(prove, \Pi^{fac}_j, (ssid, \rho, i), (N_i, \kappa); p_i, q_i)$, for all $j\ne i$
- Compute $C^j_i = enc_j(\mathrm{Sh}^j_i)$

Send $(\psi_i, \phi_{j, i}, C^j_i)$ to $\mathcal{P}_j$

### Round 4.

Upon receving $(\psi_j, \phi_{i, j}, C^i_j)$ from $\mathcal{P}_j$

- Verify $\mathcal{M}(verity, \psi_j, \Pi^{mod}, (ssid, \rho, j), N_j) = true$
- Verity $\mathcal{M}(verity, \phi_{i,j}, \Pi^{fac}_i, (ssid, \rho, j), (N_j, \kappa)) = true$, for all $j\ne i$
- Set $x^j_i = dec_i(C^j_i)$, verify $x^j_i$ is aligned with $\mathrm{Vs}_j$

When obtaining the above from all $\mathcal{P}_j$

- Set $x_i = \sum_j x^j_i$ 
- Set $\mathrm{Vs} = \sum_j \mathrm{Vs}_j$, and compute $X_j$, as well as pubkey $X_0$
- Compute $\pi_i = \mathcal{M}(proof, \Pi^{sch}, (ssid, \rho, i), X_i; x_i)$ using first message $A_i$

Broadcast $\pi_i$

### Round 5.

Upon receving $\pi_j$ from $\mathcal{P}_j$ 

- Interpret $\pi_j=(\hat{A}_j,\cdots)$, verify $\hat{A}_j=A_j$ and $\pi_i = \mathcal{M}(verify, \pi_j, \Pi^{sch}, (ssid, \rho, j), X_j)= true$


## Child Key Derivation

For presigning, the protocol always do for the master key $x$. For sigining, there is an additional input $\Delta$, the signing is sign for the derived private key $x+\Delta$, with derived public key $Y+\Delta \cdot G$.