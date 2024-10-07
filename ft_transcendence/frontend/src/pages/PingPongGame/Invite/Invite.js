import React, { useEffect, useState, useRef } from 'react';
import RealTimeGame from '../RealTimeGame.js/RealTimeGame';

export const InviteGameReconnection = () => {
    // alert("HELLO BABY");
    return(
        <div>
            <RealTimeGame mode="invite-game-reconnection"/>
        </div>
    )
}

const Invite = () => {
    return(
        <div>
            <RealTimeGame mode="invite"/>
        </div>
    )
};

export default Invite;
