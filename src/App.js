import React, { Component } from 'react';
import { HashRouter, Route } from 'react-router-dom';

import Login from './components/Login/Login'
import Private from './components/Private/Private'


class App extends Component {
  render() {
    return (
      <HashRouter>
        <div className='App'>
          <Route exact path="/" component={Login}></Route>
          <Route path="/private" component={Private}></Route>
        </div>
      </HashRouter>
    );
  }
}

export default App;
