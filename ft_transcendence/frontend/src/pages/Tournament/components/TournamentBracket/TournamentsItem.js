import React, { useState, useEffect } from 'react'
import './TournamentsItem.css'
import { avatarsUnkown } from '../../../../assets/assets';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

function TournamentsItem({players}) {
  const unknownAvatar = avatarsUnkown.img;
  const [ifPlayer1Win, setIfPlayer1Win] = useState(false)
  const [ifPlayer2Win, setIfPlayer2Win] = useState(false)



useEffect(() => {
  if (players?.player1?.username && players?.winner?.username && players.player1.username === players.winner.username) {
    setIfPlayer1Win(true);
  }
}, [players]);

useEffect(() => {
  if (players?.player2?.username && players?.winner?.username && players.player2.username === players.winner.username) {
    setIfPlayer2Win(true);
  }
}, [players]);

  return (
    <div className="tournamentsItem-match-container">
      <div className={ifPlayer1Win ? 'tournamentsItem-container wone' : 'tournamentsItem-container losse'}>
          <div className="player-image">
            <img src={players.player1?.avatar ? `${BACKEND_URL}${players.player1.avatar}` : unknownAvatar} alt={players.player1?.username || 'Unknown Player'} />
          </div>
          <div className="player-name">
            <p>{players.player1?.username || 'Unknown Player'}</p>
          </div>
      </div>
      <div className={ifPlayer2Win ? 'tournamentsItem-container wone' : 'tournamentsItem-container losse'}>
        <div className="player-image">
            <img src={players.player2?.avatar ? `${BACKEND_URL}${players.player2.avatar}` : unknownAvatar} alt={players.player2?.username || 'Unknown Player'} />

        </div>
        <div className="player-name">
          <p>{players.player2?.username || 'Unknown Player'}</p>
        </div>
        </div>
    </div>

  )
}

export default TournamentsItem