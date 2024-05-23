// `    `
const mongoose=require('mongoose');

const {Schema} =mongoose;

const placeSchema =new Schema({
    owner:{
        type: mongoose.Schema.Types.ObjectId,
        ref:'User'
    },

        title:String,
        address:String,
        photos:[String],
        description: String,
        perks:[String],
        extrainfo:String,
        checkin : Number,
        checkout : Number,
        maxguest : Number,
        price:Number

        // title:{
        //     type:String,
        //     required: true,
        //     // unique:true
        // },
        // address:{
        //     type:String,
        //     required: true,
        //     // unique:true
        // },
        // photos:[String],
        // description: {
        //     type:String,
        //     required: true,
        //     // unique:true
        // },
        // perks:[String],
        // extrainfo:String,
        // checkIn : {
        //     type:Number,
        //     required: true,
        //     // unique:true
        // },
        // checkOut :  {
        //     type:Number,
        //     required: true,
        //     // unique:true
        // },
        // maxguest :  {
        //     type:Number,
        //     required: true,
        //     // unique:true
        // },
        // price: {
        //     type:Number,
        //     required: true,
        //     // unique:true
        // }

});
const Placemodel= mongoose.model('Place',placeSchema);

module.exports= Placemodel;