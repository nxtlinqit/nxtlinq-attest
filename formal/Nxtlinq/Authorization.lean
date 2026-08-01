namespace Nxtlinq.Authorization

abbrev Capability := String

inductive Decision where
  | allow
  | deny
  deriving DecidableEq, Repr

/-- The small authorization state shared with the runtime vectors. -/
structure Request where
  manifestVerified : Bool
  artifactVerified : Bool
  signedScope : List Capability
  requestedCapability : Capability

/-- The complete decision rule: all three conditions must hold to allow. -/
def authorize (request : Request) : Decision :=
  if request.manifestVerified &&
      request.artifactVerified &&
      decide (request.requestedCapability ∈ request.signedScope) then
    .allow
  else
    .deny

/-- The model permits execution only after an allow decision. -/
def ExecutionPermitted (request : Request) : Prop := authorize request = .allow

theorem invalidSignatureNeverAuthorizes
    (request : Request)
    (invalidSignature : request.manifestVerified = false) :
    authorize request = .deny := by
  simp [authorize, invalidSignature]

theorem alteredArtifactNeverAuthorizes
    (request : Request)
    (alteredArtifact : request.artifactVerified = false) :
    authorize request = .deny := by
  simp [authorize, alteredArtifact]

theorem outOfScopeCapabilityNeverAuthorizes
    (request : Request)
    (outOfScope : request.requestedCapability ∉ request.signedScope) :
    authorize request = .deny := by
  simp [authorize, outOfScope]

theorem executionRequiresVerifiedManifestArtifactAndScope
    (request : Request)
    (executes : ExecutionPermitted request) :
    request.manifestVerified = true ∧
      request.artifactVerified = true ∧
      request.requestedCapability ∈ request.signedScope := by
  simpa [ExecutionPermitted, authorize] using executes

end Nxtlinq.Authorization
