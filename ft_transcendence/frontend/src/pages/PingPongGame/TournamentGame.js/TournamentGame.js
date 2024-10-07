import RealTimeGame from "../RealTimeGame.js/RealTimeGame";
const TournamentGame = () => {
    alert("HELLO FROM TOURNAMENT COMPONENT");

    return (
        <div>
            <RealTimeGame mode={"tournament"}/>
        </div>
    );
}
 
export default TournamentGame;