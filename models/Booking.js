

const mongoose =require ('mongoose');
const {Schema} =mongoose;
const BookingSchema=new Schema ({
    // owner:{
    //     type: mongoose.Schema.Types.ObjectId,
    //     ref:'Place'
    // },
        place:{type:mongoose.Schema.Types.ObjectId,required:true,ref:'Place'},
        user:{type:mongoose.Schema.Types.ObjectId, required:true},
        placeOwner:{type:mongoose.Schema.Types.ObjectId, required:true},
        checkIn:Date,
        checkOut:Date,
        bookingDate:Date,
        noGuest:Number,
        name:String,
        mobile:Number,
        price:Number
});

const Bookingmodel= mongoose.model('Booking',BookingSchema);

module.exports= Bookingmodel;