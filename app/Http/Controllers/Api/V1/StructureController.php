<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class StructureController extends Controller
{
    //
    public function index(Request $request){
        return response()->json([
            'message' => 'This is the index method of StructureController',
            'data' => $request->all()
        ]);
    }
}
