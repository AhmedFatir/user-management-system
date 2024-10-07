import React, { useState } from 'react';
import PingPong from './components/PingPong/PingPong';
import XO from './components/XO/XO';
import './game.css'
import pingLogo from './Game-assets/ping.svg'
import XOLogo from './Game-assets/XO.svg'

const Game = () => {
  const [selectedGame, setSelectedGame] = useState('ping-pong');

  const handleSelectGame = (game) => {
    setSelectedGame(game);
  };

  return (
    <div className='game-container'>
        <div className='page-title'>
          <h1>Game Lobby</h1>
          <PingPong/>
        </div>
    </div>
  )
}

export default Game