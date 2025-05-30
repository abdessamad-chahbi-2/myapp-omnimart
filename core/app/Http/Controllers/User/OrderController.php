<?php

namespace App\Http\Controllers\User;

use App\{
    Models\Order,
    Http\Controllers\Controller
};

use Auth;

class OrderController extends Controller
{

    /**
     * Constructor Method.
     *
     * Setting Authentication
     *
     */

    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('localize');

    }

    public function index()
    {
        $orders = Order::whereUserId(Auth::user()->id)->latest('id')->get();
        return view('user.order.index',compact('orders'));
    }

  
    public function details($id)
    {
        $user = Auth::user();
        $order = Order::findOrfail($id);
        $cart = json_decode($order->cart, true);
        return view('user.order.invoice',compact('user','order','cart'));
    }

    public function printOrder($id)
    {
        $user = Auth::user();
        $order = Order::findOrfail($id);
        $cart = json_decode($order->cart, true);
        return view('user.order.print',compact('user','order','cart'));
    }
}
