import {
  Field,
  MerkleWitness,
  Poseidon,
  PrivateKey,
  PublicKey,
  SmartContract,
  State,
  method,
  state,
} from 'snarkyjs';

const authorizer = PrivateKey.fromBase58(
  'EKFAdBGSSXrBbaCVqy4YjwWHoGEnsqYRQTqz227Eb5bzMx2bWu3F'
);

class AgeMerkleWitness extends MerkleWitness(10) {} // can store up to 2^10 values

export class ZkAgeGroup extends SmartContract {
  @state(Field) below18GroupRoot = State<Field>();
  @state(Field) above18GroupRoot = State<Field>();
  @state(Field) below21GroupRoot = State<Field>();
  @state(Field) above21GroupRoot = State<Field>();

  @state(PublicKey) authorizer = State<PublicKey>();

  init() {
    super.init();
    this.authorizer.set(authorizer.toPublicKey());
  }

  @method updateRoot(
    authorizerPrivateKey: PrivateKey,
    below18GroupRoot: Field,
    above18GroupRoot: Field,
    below21GroupRoot: Field,
    above21GroupRoot: Field
  ) {
    const authorizerPublicKey = this.authorizer.get();
    this.authorizer.assertEquals(authorizerPublicKey);

    authorizerPublicKey.assertEquals(authorizerPrivateKey.toPublicKey()); // only authorizer can update the root
    this.below18GroupRoot.set(below18GroupRoot);
    this.above18GroupRoot.set(above18GroupRoot);
    this.below21GroupRoot.set(below21GroupRoot);
    this.above21GroupRoot.set(above21GroupRoot);
  }

  @method verifyInBelow18Group(user: PublicKey, path: AgeMerkleWitness) {
    const below18GroupRoot = this.below18GroupRoot.get();
    this.below18GroupRoot.assertEquals(below18GroupRoot);

    const leafNode = Poseidon.hash([user.x]);

    path.calculateRoot(leafNode).assertEquals(below18GroupRoot);
  }

  @method verifyInAbove18Group(user: PublicKey, path: AgeMerkleWitness) {
    const above18GroupRoot = this.above18GroupRoot.get();
    this.above18GroupRoot.assertEquals(above18GroupRoot);

    const leafNode = Poseidon.hash([user.x]);

    path.calculateRoot(leafNode).assertEquals(above18GroupRoot);
  }
  @method verifyInBelow21Group(user: PublicKey, path: AgeMerkleWitness) {
    const below18GroupRoot = this.below18GroupRoot.get();
    this.below18GroupRoot.assertEquals(below18GroupRoot);

    const leafNode = Poseidon.hash([user.x]);

    path.calculateRoot(leafNode).assertEquals(below18GroupRoot);
  }

  @method verifyInAbove21Group(user: PublicKey, path: AgeMerkleWitness) {
    const above18GroupRoot = this.above18GroupRoot.get();
    this.above18GroupRoot.assertEquals(above18GroupRoot);

    const leafNode = Poseidon.hash([user.x]);

    path.calculateRoot(leafNode).assertEquals(above18GroupRoot);
  }
}
