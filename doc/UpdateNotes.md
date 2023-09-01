# Notes for PR #113

## Current Dev Branches

- SuperCold
  - iOS: mobile-wrapper(release/1.6.0) 
    - tss-lib-private: v1.6.0-go15

- ColdGuardian
  - iOS: mpcsdk(0.23.0)
    - tss-lib-private: v1.6.0-go15.0.20230307070646-2cd8828d1908

- Cosign
  - iOS: mpcsdk(0.32.2)
    - tss-lib-private: v1.6.2-go15.0.20230720070510-4b8bf873d19e
  - Android:: mpcsdk(0.32.2)
      - tss-lib-private: v1.6.2-go15.0.20230720070510-4b8bf873d19e

- BUW
  - iOS: mpcsdk(0.25.0)
    - tss-lib-private: v1.6.0-go15.0.20230519032244-d34804e85604
  - Android: mpcsdk(0.25.1)
      - tss-lib-private: v1.6.0-go15.0.20230519032244-d34804e85604

## Noticable changes

* ZIL/Mina Schnorr protocol
* KCDSA protocol
* ToB audit security updates
    * BLS curve renamed to BLS12381G1, BLS12381G2
    * Update edwards25519 impl, remove dep of private fork
* Restore private sk function(from Fitz)
* ContextJ issue (used to cause a low probability of fail to verify correct proofs received)
* Non-hardened child key derivation for all protocols(include ZIL/Mina SChnorr, KCDSA)
* (derivekey protocol) Hardened child key derivation protocol
* RejectSample update (serious security bug, not backward compatible)
* Hash function update (not backward compatible)
* Frost keygen protocol and faster ECDSA keygen

## Commitments that are not included

### (2cd8828d)
![img_1.png](img_1.png)

### (4b8bf87)
![img_2.png](img_2.png)

### (d34804e)
![img_3.png](img_3.png)

## Migration Guide of Faster ECDSA Keygen

1. for ecdsa keygen_fast we only generate xi, shareXi, pubkey

2. for ecdsa postkeygen we will generate Paillier key and run trusted setup.

3. so once ecdsa keygen done, we can tell user the key has been generated. (in 1 second)

4. you can decide when to run paillier key trusted setup, once paillier key negotiation done, we can let user do further rounds. (in 20 seconds)

### example

#### NewLocalParty
```go=
keygen_fast.NewLocalParty(params, outCh, endCh)
postkeygen.NewLocalParty(params, outCh, endCh, preParams) // preParams is optional
```

#### Accept Results
**write to same file for usage, ensure they are in same json format with original ecdsa keygen.**
```go=
func tryWriteTestFixtureFile(t *testing.T, index int, data keygen.LocalPartySaveData) {
	fixtureFileName := makeTestFixtureFilePath(index)

	dir := path.Dir(fixtureFileName)
	err := os.MkdirAll(dir, 0751)
	assert.NoError(t, err)
	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			t.Fatalf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		if err != nil {
			assert.NoErrorf(t, err, "unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := ioutil.ReadFile(fixtureFileName)
		if err != nil {
			assert.NoErrorf(t, err, "unable to open read file all %s", fixtureFileName)
		}
		var inObj keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &inObj); err != nil {
			assert.NoErrorf(t, err, "unable to unmaarshal json %s", fixtureFileName)
		}
		for _, kbxj := range inObj.BigXj {
			if kbxj != nil {
				kbxj.SetCurve(tss.S256())
			}
		}
		if inObj.ECDSAPub != nil {
			inObj.ECDSAPub.SetCurve(tss.S256())
		}
		// if no paillier keys
		if inObj.NTildej == nil || inObj.NTildej[0] == nil {
			inObj.NTildej = data.NTildej
			inObj.H1j = data.H1j
			inObj.H2j = data.H2j
			inObj.PaillierPKs = data.PaillierPKs
			inObj.LocalPreParams = data.LocalPreParams
			fmt.Println("patched pallier")
		}

		// if no xi
		if inObj.Xi == nil {
			inObj.Xi = data.Xi
			inObj.ShareID = data.ShareID
			fmt.Println("patched Xi")
		}

		t.Logf("Fixture file already exists for party %d; try scanning any attributes to add: %s", index, fixtureFileName)
		fd, err := os.OpenFile(fixtureFileName, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
		bzs, err := json.Marshal(inObj)
		_, err = fd.Write(bzs)
		if err != nil {
			t.Fatalf("unable to write to fixture file %s", fixtureFileName)
		}
		t.Logf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	}
}
```


### Compatibility Change
If not all parties update, `RejectionSampleVersion` needs to be controlled.
```go=
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int, 
                   needsIdentification bool, nonce int,
                   opts ...ConfigOpt) *Parameters { ... }


func WithRejectionSampleVersion(version RejectionSampleVersion) ConfigOpt {
	return func(config *Config) error {
		config.VersionInfo = NewVersion(WithRejectionSample(version))
		return nil
	}
}

func WithSafePrimeGenTimeout(duration time.Duration) ConfigOpt {
	return func(config *Config) error {
		config.SafePrimeTimeout = duration
		return nil
	}
}

// usage 
params := tss.NewParameters(tss.EC(), p2pCtx, pIDs[0], len(pIDs), threshold, false, 0, 
                            tss.WithRejectionSampleVersion(tss.RejectionSampleV1), 
                            tss.WithSafePrimeGenTimeout(time.Millisecond*1000))

```
