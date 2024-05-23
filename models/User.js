const mongoose =require('mongoose');
const {Schema} = mongoose;
const UserSchema= new Schema({
    name:{type:String},
    email:{type:String, unique:true},
    phoneno:{type:Number, unique:true},
    password:{type:String}
});
// for creating a new schema as per ur need
const UserModel=mongoose.model('User',UserSchema);
// export default User;
module.exports=UserModel;