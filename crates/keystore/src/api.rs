mod gen; 

use keystore::valv::keystore::v1::MasterKey;


fn main() {
    println!("{:?}", MasterKey::default());
}
