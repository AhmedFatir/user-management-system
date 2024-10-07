import React, { useEffect, useState, useRef } from 'react';
import RealTimeGame from '../RealTimeGame.js/RealTimeGame';



const Random = () => {
    return (
        <div>
            <RealTimeGame mode={"random"}/>
        </div>
    )
};

export default Random;
